//! Private bounded operational DATA. No decoder or authority reconstruction.
use crate::storage_driver::private_fs::Dir;
use sha2::{Digest,Sha256};
use std::fs::File;
use std::io::Write;
use std::os::unix::fs::{MetadataExt,FileExt};
use std::sync::{Arc,Mutex};

pub(super) const PAGE_BYTES:usize=32768;
pub(super) const PREFIX_BYTES:usize=128;
pub(super) const FRAME_BYTES:usize=80;
pub(super) const ATTACH_HEADER_BYTES:usize=23552;
const MAGIC:[u8;16]=*b"ROYAK-JOURNAL2!!";
const DOMAIN:&[u8]=b"royak-runtime-evidence-frame-v2";

fn digest(raw:&[u8])->[u8;32]{Sha256::digest(raw).into()}
pub(super) fn exact_hash(raw:&str)->Result<[u8;32],String>{
    if raw.len()!=64 || !raw.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b)){
        return Err("invalid exact full evidence SHA256".into());
    }
    let mut result=[0;32];
    for (i,pair) in raw.as_bytes().chunks_exact(2).enumerate(){
        fn digit(x:u8)->u8{if x<=b'9'{x-b'0'}else{x-b'a'+10}}
        result[i]=(digit(pair[0])<<4)|digit(pair[1]);
    }
    Ok(result)
}
fn chain(header:&[u8;32],previous:&[u8;32],sequence:u64,kind:u16,payload:&[u8;32])->[u8;32]{
    let mut h=Sha256::new();h.update(DOMAIN);h.update(header);h.update(previous);
    h.update(sequence.to_be_bytes());h.update(kind.to_be_bytes());h.update(payload);h.finalize().into()
}
fn prefix(index:usize,header_len:usize,maximum:usize,header:&[u8;32],previous:&[u8;32])->[u8;PREFIX_BYTES]{
    let mut value=[0;PREFIX_BYTES];value[..16].copy_from_slice(&MAGIC);
    value[16..20].copy_from_slice(&2u32.to_be_bytes());
    value[20..24].copy_from_slice(&(index as u32).to_be_bytes());
    value[24..28].copy_from_slice(&(header_len as u32).to_be_bytes());
    value[28..32].copy_from_slice(&(maximum as u32).to_be_bytes());
    value[32..64].copy_from_slice(header);value[64..96].copy_from_slice(previous);value
}
fn frame(sequence:u64,kind:u16,payload:&[u8;32],result:&[u8;32])->[u8;FRAME_BYTES]{
    let mut value=[0;FRAME_BYTES];value[..8].copy_from_slice(&sequence.to_be_bytes());
    value[8..10].copy_from_slice(&kind.to_be_bytes());value[16..48].copy_from_slice(payload);
    value[48..80].copy_from_slice(result);value
}
fn capacity(header:usize,pages:usize)->Option<usize>{
    if pages==0 || pages>2 || header>PAGE_BYTES.checked_sub(PREFIX_BYTES)?{return None;}
    let first=(PAGE_BYTES-PREFIX_BYTES-header)/FRAME_BYTES;
    Some(first+(pages-1)*((PAGE_BYTES-PREFIX_BYTES)/FRAME_BYTES))
}
fn stamp(m:&std::fs::Metadata)->(u64,u64,u32,u32,u32,u64,u64,i64,i64,i64,i64){
    (m.dev(),m.ino(),m.uid(),m.gid(),m.mode(),m.nlink(),m.len(),m.mtime(),m.mtime_nsec(),m.ctime(),m.ctime_nsec())
}
fn verify_content(dir:&Dir,name:&str,file:&File,identity:(u64,u64),len:usize,expected:[u8;32])->Result<(),String>{
    dir.verify_retained_page(name,file,identity,len as u64,PAGE_BYTES as u64)?;
    let before=file.metadata().map_err(|_|"original evidence readback metadata UNKNOWN")?;
    let mut hash=Sha256::new();let mut at=0;let mut buffer=[0u8;4096];
    while at<len{
        let count=(len-at).min(buffer.len());
        let read=file.read_at(&mut buffer[..count],at as u64).map_err(|_|"original evidence readback UNKNOWN")?;
        if read==0{return Err("original evidence readback premature EOF; UNKNOWN".into());}
        hash.update(&buffer[..read]);at+=read;
    }
    let mut extra=[0];
    if file.read_at(&mut extra,len as u64).map_err(|_|"original evidence EOF UNKNOWN")?!=0{
        return Err("original evidence readback grew; UNKNOWN".into());
    }
    let after=file.metadata().map_err(|_|"original evidence post-read metadata UNKNOWN")?;
    let actual:[u8;32]=hash.finalize().into();
    if stamp(&before)!=stamp(&after)||actual!=expected{return Err("original evidence bytes/header/frame/link changed; UNKNOWN".into());}
    dir.verify_retained_page(name,file,identity,len as u64,PAGE_BYTES as u64)
}
struct Page {name:String,file:File,identity:Option<(u64,u64)>,len:usize,expected:Sha256}
impl Page {
    fn verify(&self,dir:&Dir)->Result<(),String>{verify_content(dir,&self.name,&self.file,
        self.identity.ok_or("original evidence identity absent")?,self.len,self.expected.clone().finalize().into())}
}
#[cfg(test)]
#[derive(Clone,Copy,PartialEq,Eq)]
enum Fault {AfterOpen,AfterFrameWrite,AfterFrameSync}
struct State {pages:Vec<Page>,sequence:usize,chain:[u8;32],poisoned:bool,#[cfg(test)] fault:Option<Fault>}
struct ExactState {file:Option<File>,started:bool}
/// Exact original canonical JSON, without a new smaller input envelope. The
/// original FD is retained before every fallible observation/write, also when
/// an old full32KiB cold payload cannot carry binary framing overhead.
pub(super) struct ExactRecord {dir:Arc<Dir>,name:String,raw:Vec<u8>,state:Mutex<ExactState>}
impl ExactRecord {
    pub(super) fn new(dir:Arc<Dir>,name:String,raw:Vec<u8>)->Result<Self,String>{
        if raw.is_empty()||raw.len()>PAGE_BYTES{return Err("exact bounded evidence record exceeds original32KiB".into());}
        Ok(Self {dir,name,raw,state:Mutex::new(ExactState{file:None,started:false})})
    }
    pub(super) fn write_once(&self)->Result<(),String>{
        let mut state=self.state.lock().map_err(|_|"exact evidence owner poisoned")?;
        if state.started{return Err("exact evidence already attempted; never retry".into());}
        state.started=true;
        let original=self.dir.create_retained_page(&self.name)?;
        state.file=Some(original); // root before ANY later fallible operation
        let file=state.file.as_ref().expect("original exact FD rooted");
        let m=file.metadata().map_err(|_|"exact evidence FD metadata UNKNOWN")?;
        let identity=(m.dev(),m.ino());
        self.dir.verify_retained_page(&self.name,file,identity,0,PAGE_BYTES as u64)?;
        let mut output=file;output.write_all(&self.raw).map_err(|_|"exact evidence write UNKNOWN")?;
        file.sync_all().map_err(|_|"exact evidence fsync UNKNOWN")?;
        self.dir.sync_retained_directory()?;
        verify_content(&self.dir,&self.name,file,identity,self.raw.len(),digest(&self.raw))
    }
}
/// Journal roots this exact object BEFORE open/header/append/fsync. Neither
/// caller Drop nor a failed future may close an unknown original page FD.
pub(super) struct JobWriter {
    dir:Arc<Dir>,name:String,header:Vec<u8>,header_hash:[u8;32],maximum:usize,
    maximum_pages:usize,state:Mutex<State>,
}
impl JobWriter {
    pub(super) fn require_header(&self,actual:&[u8])->Result<(),String>{
        if actual!=self.header.as_slice(){return Err("actual job's exact pinned header changed; UNKNOWN".into());}Ok(())
    }
    pub(super) fn initialize(&self)->Result<(),String>{
        let mut state=self.state.lock().map_err(|_|"retained evidence writer poisoned")?;
        if state.poisoned||!state.pages.is_empty(){return Err("evidence header already attempted; no retry".into());}
        state.poisoned=true;self.add_page(&mut state)?;state.poisoned=false;Ok(())
    }
    pub(super) fn new(dir:Arc<Dir>,name:String,header:Vec<u8>,maximum:usize,pages:usize)->Result<Self,String>{
        if maximum==0 || maximum>512 || capacity(header.len(),pages).is_none_or(|n|n<maximum)
            || pages==2 && header.len()>ATTACH_HEADER_BYTES {
            return Err("complete exact job header/record budget cannot fit reserved pages".into());
        }
        let header_hash=digest(&header);
        Ok(Self {dir,name,header,header_hash,maximum,maximum_pages:pages,
            state:Mutex::new(State {pages:Vec::with_capacity(pages),sequence:0,chain:[0;32],poisoned:false,#[cfg(test)] fault:None})})
    }
    fn add_page(&self,state:&mut State)->Result<(),String>{
        let index=state.pages.len();
        if index>=self.maximum_pages{return Err("reserved evidence pages exhausted; UNKNOWN".into());}
        let name=format!("{}-p{index}.jrn",self.name);
        let file=self.dir.create_retained_page(&name)?;
        // No fallible read/write after successful open until SAME File is in
        // this Journal-rooted object. Partial initial headers remain retained.
        state.pages.push(Page {name,file,identity:None,len:0,expected:Sha256::new()});
        #[cfg(test)]
        if state.fault==Some(Fault::AfterOpen){return Err("TEST injected failure after original FD rooted".into());}
        let p=state.pages.last_mut().expect("page just rooted");
        let metadata=p.file.metadata().map_err(|_|"new evidence FD identity UNKNOWN")?;
        let identity=(metadata.dev(),metadata.ino());p.identity=Some(identity);
        self.dir.verify_retained_page(&p.name,&p.file,identity,0,PAGE_BYTES as u64)?;
        let header=if index==0{self.header.as_slice()}else{&[]};
        let framing=prefix(index,header.len(),self.maximum,&self.header_hash,&state.chain);
        let mut original=&p.file;
        original.write_all(&framing).map_err(|_|"evidence page prefix write UNKNOWN")?;
        original.write_all(header).map_err(|_|"evidence exact header write UNKNOWN")?;
        p.file.sync_all().map_err(|_|"evidence exact header fsync UNKNOWN")?;
        self.dir.sync_retained_directory()?;
        p.len=PREFIX_BYTES+header.len();
        p.expected.update(framing);p.expected.update(header);p.verify(&self.dir)
    }
    pub(super) fn append(&self,kind:u16,payload:[u8;32])->Result<(),String>{
        let mut state=self.state.lock().map_err(|_|"retained evidence writer poisoned")?;
        if state.poisoned {
            return Err("evidence writer UNKNOWN/exhausted/invalid; no retry".into());
        }
        if state.sequence>=self.maximum||kind==0{state.poisoned=true;return Err("evidence writer admission exhausted/invalid; UNKNOWN".into());}
        // Sticky until ALL original writes/fsync/anchored rechecks succeed.
        // Any error retains both exact pages and the consumed operation state.
        state.poisoned=true;
        for page in &state.pages{page.verify(&self.dir)?;}
        if state.pages.last().is_none_or(|p|p.len+FRAME_BYTES>PAGE_BYTES){self.add_page(&mut state)?;}
        let sequence=(state.sequence+1) as u64;
        let next=chain(&self.header_hash,&state.chain,sequence,kind,&payload);
        let bytes=frame(sequence,kind,&payload,&next);
        #[cfg(test)] let fault=state.fault;
        let p=state.pages.last_mut().expect("page initialized");
        let identity=p.identity.ok_or("original page identity absent; UNKNOWN")?;
        self.dir.verify_retained_page(&p.name,&p.file,identity,p.len as u64,PAGE_BYTES as u64)?;
        let mut original=&p.file;
        original.write_all(&bytes).map_err(|_|"evidence admission append UNKNOWN")?;
        #[cfg(test)]
        if fault==Some(Fault::AfterFrameWrite){return Err("TEST injected fsync failure after actual append".into());}
        p.file.sync_all().map_err(|_|"evidence admission fsync UNKNOWN; never grant")?;
        #[cfg(test)]
        if fault==Some(Fault::AfterFrameSync){return Err("TEST injected late outcome after actual fsync".into());}
        p.len+=FRAME_BYTES;
        p.expected.update(bytes);
        for page in &state.pages{page.verify(&self.dir)?;}
        state.sequence+=1;state.chain=next;state.poisoned=false;Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_512_full_hash_records_fit_two_original_32k_pages(){
        assert_eq!(capacity(ATTACH_HEADER_BYTES,2),Some(521));
        let first=(PAGE_BYTES-PREFIX_BYTES-ATTACH_HEADER_BYTES)/FRAME_BYTES;
        assert_eq!(first,113);assert_eq!(512-first,399);
        assert_eq!(PREFIX_BYTES+ATTACH_HEADER_BYTES+first*FRAME_BYTES,32720);
        assert_eq!(PREFIX_BYTES+(512-first)*FRAME_BYTES,32048);
        assert!(capacity(ATTACH_HEADER_BYTES,1).unwrap()<512);
    }
    #[test]
    fn evidence_chain_binds_every_full_hash_sequence_purpose_and_header(){
        let header=[1;32];let previous=[2;32];let payload=[3;32];
        let expected=chain(&header,&previous,1,9,&payload);
        for changed in [chain(&[4;32],&previous,1,9,&payload),chain(&header,&[4;32],1,9,&payload),
            chain(&header,&previous,2,9,&payload),chain(&header,&previous,1,10,&payload),chain(&header,&previous,1,9,&[4;32])]{
            assert_ne!(expected,changed);
        }
        let bytes=frame(1,9,&payload,&expected);assert_eq!(&bytes[16..48],&payload);assert_eq!(&bytes[48..],&expected);
        assert_eq!(&bytes[10..16],&[0;6]);
    }
    #[test]
    fn malformed_or_short_or_uppercase_evidence_hash_never_becomes_zero(){
        assert_eq!(exact_hash(&"f".repeat(64)).unwrap(),[255;32]);
        for raw in ["".into(),"a".repeat(63),"a".repeat(65),"A".repeat(64),"g".repeat(64)]{assert!(exact_hash(&raw).is_err());}
        assert!(capacity(PAGE_BYTES,2).is_none());assert!(capacity(0,3).is_none());
    }
    struct OwnedTemp {root:std::path::PathBuf,dir:Arc<Dir>}
    impl OwnedTemp {
        fn new()->Self{
            let root=std::fs::canonicalize(std::env::temp_dir()).unwrap()
                .join(format!("royak-journal-data-{}",crate::storage_identity::Uid::new().as_str()));
            let dir=Arc::new(Dir::open(&root,true).unwrap());Self{root,dir}
        }
    }
    impl Drop for OwnedTemp{fn drop(&mut self){std::fs::remove_dir_all(&self.root).unwrap();}}
    #[test]
    fn actual_owned_temp_pages_fsync_all512_then_refuse513_without_losing_fds(){
        let temp=OwnedTemp::new();
        let writer=JobWriter::new(temp.dir.clone(),"all512".into(),vec![b'x';ATTACH_HEADER_BYTES],512,2).unwrap();
        writer.initialize().unwrap();
        for sequence in 0u64..512{writer.append(411,digest(&sequence.to_be_bytes())).unwrap();}
        {let s=writer.state.lock().unwrap();assert_eq!(s.sequence,512);assert_eq!(s.pages.len(),2);
            assert_eq!(s.pages[0].len,32720);assert_eq!(s.pages[1].len,32048);
            for p in &s.pages{assert_eq!(p.file.metadata().unwrap().len(),p.len as u64);}}
        assert!(writer.append(411,[0;32]).is_err());
        let s=writer.state.lock().unwrap();assert!(s.poisoned);assert_eq!(s.pages.len(),2);
        assert!(s.pages.iter().all(|p|p.file.metadata().is_ok()));
    }
    #[test]
    fn actual_page_open_write_and_late_fsync_faults_retain_original_fds_unknown(){
        for fault in [Fault::AfterOpen,Fault::AfterFrameWrite,Fault::AfterFrameSync]{
            let temp=OwnedTemp::new();let writer=JobWriter::new(temp.dir.clone(),"fault".into(),b"{}".to_vec(),2,1).unwrap();
            if fault!=Fault::AfterOpen{writer.initialize().unwrap();}
            writer.state.lock().unwrap().fault=Some(fault);
            let result=if fault==Fault::AfterOpen{writer.initialize()}else{writer.append(201,[1;32])};
            assert!(result.is_err());
            {let s=writer.state.lock().unwrap();assert!(s.poisoned);assert_eq!(s.pages.len(),1);
                assert!(s.pages[0].file.metadata().is_ok());assert_eq!(s.sequence,0);}
            assert!(writer.append(201,[2;32]).is_err());
        }
    }
    #[test]
    fn actual_page_path_replacement_and_extra_hardlink_refuse_with_original_fd_held(){
        for hardlink in [false,true]{
            let temp=OwnedTemp::new();let writer=JobWriter::new(temp.dir.clone(),"identity".into(),b"{}".to_vec(),2,1).unwrap();
            writer.initialize().unwrap();let name=temp.root.join("identity-p0.jrn");let alias=temp.root.join("own-alias");
            if hardlink{std::fs::hard_link(&name,&alias).unwrap();}
            else{std::fs::rename(&name,&alias).unwrap();std::fs::write(&name,b"{}").unwrap();}
            assert!(writer.append(201,[1;32]).is_err());let s=writer.state.lock().unwrap();
            assert!(s.poisoned);assert_eq!(s.pages.len(),1);assert!(s.pages[0].file.metadata().is_ok());
        }
    }
    #[test]
    fn actual_same_inode_same_length_header_old_frame_and_page_link_corruption_blocks_next_append(){
        for (page,offset) in [(0,0),(0,PREFIX_BYTES),(0,32719),(1,64),(1,PREFIX_BYTES+16)]{
            let temp=OwnedTemp::new();let writer=JobWriter::new(temp.dir.clone(),"tamper".into(),vec![b'x';ATTACH_HEADER_BYTES],512,2).unwrap();
            writer.initialize().unwrap();for i in 0u64..114{writer.append(411,digest(&i.to_be_bytes())).unwrap();}
            let (path,identity,len)={let s=writer.state.lock().unwrap();let p=&s.pages[page];
                (temp.root.join(&p.name),p.identity.unwrap(),p.len)};
            let changed=std::fs::OpenOptions::new().read(true).write(true).open(&path).unwrap();
            let mut old=[0];assert_eq!(changed.read_at(&mut old,offset as u64).unwrap(),1);
            assert_eq!(changed.write_at(&[old[0]^1],offset as u64).unwrap(),1);changed.sync_all().unwrap();
            let m=changed.metadata().unwrap();assert_eq!((m.dev(),m.ino()),identity);assert_eq!(m.len(),len as u64);
            assert!(writer.append(411,[9;32]).is_err());let s=writer.state.lock().unwrap();
            assert!(s.poisoned);assert_eq!(s.sequence,114);assert_eq!(s.pages.len(),2);
            assert_eq!(s.pages[page].identity,Some(identity));assert!(s.pages[page].file.metadata().is_ok());
        }
    }
}
