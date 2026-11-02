//! Private Unix fake, never Docker/containers/real signals. Linux uses real
//! SCM credentials from the copied root-private dockerd-named test child.
use super::*;
use std::sync::{Arc,Mutex,Condvar,atomic::{AtomicBool,AtomicUsize,Ordering}};
use std::os::unix::{net::UnixListener,fs::{DirBuilderExt,PermissionsExt}};
#[path="exec_fixture.rs"]
mod fixture;
const CID:&str="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const EID:&str="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
fn isolated(name:&str)->bool{
    fixture::isolated(module_path!(),name,"ROYAK_PRE_HIJACK_ISOLATED",true)
}
fn event(pair:&Arc<(Mutex<bool>,Condvar)>){let (m,c)=&**pair;*m.lock().unwrap()=true;c.notify_all();}
fn await_event(pair:&Arc<(Mutex<bool>,Condvar)>){let(m,c)=&**pair;let g=m.lock().unwrap();let(g,t)=c.wait_timeout_while(g,Duration::from_secs(3),|v|!*v).unwrap();assert!(*g&&!t.timed_out(),"fake barrier not reached");}
fn reply(s:&mut UnixStream,code:u16,body:&str){let _=s.write_all(format!("HTTP/1.1 {code} TEST\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).as_bytes());}
fn disconnected_read(result:&std::io::Result<usize>)->bool{
    matches!(result,Ok(0)) || result.as_ref().err().is_some_and(|e|matches!(e.kind(),
        std::io::ErrorKind::ConnectionReset|std::io::ErrorKind::ConnectionAborted|
        std::io::ErrorKind::BrokenPipe|std::io::ErrorKind::UnexpectedEof))
}
struct Fake{
    dir:std::path::PathBuf,old:Option<String>,stop:Arc<AtomicBool>,mode:Arc<AtomicUsize>,
    queued:Arc<(Mutex<bool>,Condvar)>,probe:Arc<(Mutex<bool>,Condvar)>,probed:Arc<(Mutex<bool>,Condvar)>,release:Arc<(Mutex<bool>,Condvar)>,ended:Arc<(Mutex<bool>,Condvar)>,
    observation:Arc<AtomicUsize>,server:Option<std::thread::JoinHandle<()>>,workers:Arc<Mutex<Vec<std::thread::JoinHandle<()>>>>,
    _journal:fixture::JournalScope,
}
impl Fake{
    fn new(head_first:bool)->Self{
        let mut journal=fixture::JournalScope::new();
        let dir=std::path::PathBuf::from("/tmp").join(format!("rkh-{}",crate::storage_identity::Uid::new().as_str()));
        std::fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();let path=dir.join("d.sock");let listener=UnixListener::bind(&path).unwrap();listener.set_nonblocking(true).unwrap();
        std::fs::set_permissions(&path,std::fs::Permissions::from_mode(0o600)).unwrap();journal.pin_socket(&path);
        let stop=Arc::new(AtomicBool::new(false));let mode=Arc::new(AtomicUsize::new(0));let created=Arc::new(AtomicBool::new(false));
        let queued=Arc::new((Mutex::new(false),Condvar::new()));let probe=Arc::new((Mutex::new(false),Condvar::new()));let probed=Arc::new((Mutex::new(false),Condvar::new()));let release=Arc::new((Mutex::new(false),Condvar::new()));let ended=Arc::new((Mutex::new(false),Condvar::new()));let observation=Arc::new(AtomicUsize::new(0));let workers=Arc::new(Mutex::new(vec![]));
        let(st,m,q,p,pd,r,end,obs,ws)=(stop.clone(),mode.clone(),queued.clone(),probe.clone(),probed.clone(),release.clone(),ended.clone(),observation.clone(),workers.clone());
        let server=std::thread::spawn(move||{
            while !st.load(Ordering::SeqCst){match listener.accept(){
                Ok((mut s,_))=>{let(m,q,p,pd,r,end,obs,created)=(m.clone(),q.clone(),p.clone(),pd.clone(),r.clone(),end.clone(),obs.clone(),created.clone());
                    ws.lock().unwrap().push(std::thread::spawn(move||{
                        s.set_nonblocking(false).unwrap();s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
                        let mut attested=false;
                        while let Some((line,body))=fixture::request(&mut s){
                            if line=="GET /info HTTP/1.1"{assert!(!attested);fixture::info(&mut s);attested=true;continue;}
                            if line=="GET /containers/json?all=1 HTTP/1.1"{
                                assert!(attested);reply(&mut s,200,&format!(r#"[{{"Id":"{CID}","Labels":{{"royak.cluster":"aabbccddeeff","royak.node":"fixture"}}}}]"#));
                            }else if line==format!("POST /containers/{CID}/exec HTTP/1.1"){
                                assert!(attested,"Create must reuse Info-attested socket");
                                let request:serde_json::Value=serde_json::from_slice(&body).unwrap();assert_eq!(request["Env"].as_array().unwrap().len(),1);
                                assert!(!created.swap(true,Ordering::SeqCst),"Create is one-shot");reply(&mut s,201,&format!(r#"{{"Id":"{EID}"}}"#));
                            }else if line==format!("POST /exec/{EID}/start HTTP/1.1"){
                                assert!(attested,"Start must reuse Info-attested socket");
                                let upgrade=b"HTTP/1.1 101 UPGRADED\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n";
                                s.set_read_timeout(Some(Duration::from_millis(150))).unwrap();
                                if head_first{let _=s.write_all(upgrade);}event(&q);await_event(&p);
                                let mut b=[0];
                                let observed=match s.read(&mut b){Ok(0)=>2,Ok(_)=>3,Err(e)if matches!(e.kind(),std::io::ErrorKind::WouldBlock|std::io::ErrorKind::TimedOut)=>1,Err(_)=>4};obs.store(observed,Ordering::SeqCst);event(&pd);
                                await_event(&r);if !head_first{let _=s.write_all(upgrade);}
                                let _=s.set_read_timeout(Some(Duration::from_secs(2)));
                                if disconnected_read(&read_uninterrupted(&mut s,&mut b)){event(&end);}
                            }else if line==format!("GET /exec/{EID}/json HTTP/1.1"){
                                let state=m.load(Ordering::SeqCst);let running=state==1;let exit=if state==2{"0"}else{"null"};reply(&mut s,200,&format!(r#"{{"ID":"{EID}","ContainerID":"{CID}","Running":{running},"ExitCode":{exit},"Pid":0}}"#));
                            }else if line==format!("GET /containers/{CID}/json HTTP/1.1"){
                                let execs=if created.load(Ordering::SeqCst){format!(r#"["{EID}"]"#)}else{"null".into()};
                                reply(&mut s,200,&format!(r#"{{"Id":"{CID}","ExecIDs":{execs}}}"#));
                            }else{panic!("unexpected fake request {line}");}
                            break;
                        }
                    }));
                },Err(e)if e.kind()==std::io::ErrorKind::WouldBlock=>std::thread::sleep(Duration::from_millis(1)),Err(e)=>panic!("{e}"),
            }}
        });
        let old=std::env::var("DOCKER_HOST").ok();std::env::set_var("DOCKER_HOST",format!("unix://{}",path.display()));
        journal.start_agent();
        Self{dir,old,stop,mode,queued,probe,probed,release,ended,observation,server:Some(server),workers,_journal:journal}
    }
    fn probe_open(&self)->bool{event(&self.probe);await_event(&self.probed);self.observation.load(Ordering::SeqCst)==1}
}
impl Drop for Fake{fn drop(&mut self){
    self._journal.stop_agent();
    event(&self.probe);event(&self.release);self.stop.store(true,Ordering::SeqCst);
    let mut failed=false;if let Some(s)=self.server.take(){failed|=s.join().is_err();}
    for w in self.workers.lock().unwrap_or_else(|e|e.into_inner()).drain(..){failed|=w.join().is_err();}
    if let Some(v)=self.old.take(){std::env::set_var("DOCKER_HOST",v);}else{std::env::remove_var("DOCKER_HOST");}
    fixture::cleanup(std::fs::remove_file(self.dir.join("d.sock")),"exact fake socket");fixture::cleanup(std::fs::remove_dir(&self.dir),"exact fake directory");
    if failed{fixture::cleanup(Err(std::io::Error::other("fake worker panicked")),"fake workers");}
}}

fn cancellation_case(head_first:bool){
    let fake=Fake::new(head_first);let cancel=SocketCancellation::default();let(_,stream)=exec_hijack(CID,&["sleep","60"],false,&cancel).unwrap();await_event(&fake.queued);
    cancel.cancel();drop(stream);assert!(!cancel.finish_execs().unwrap(),"null is not completion");assert!(cancel.has_execs());
    let open=fake.probe_open();fake.mode.store(2,Ordering::SeqCst);event(&fake.release);assert!(cancel.finish_execs().unwrap());await_event(&fake.ended);
    assert!(open,"baseline bug: cancel sent EOF before daemon start witness (observation {}: 1=open,2=EOF)",fake.observation.load(Ordering::SeqCst));
}
#[test]fn cancellation_before_hijack_does_not_abort_submitted_start(){if isolated("cancellation_before_hijack_does_not_abort_submitted_start"){return;}cancellation_case(false);}
#[test]fn late_101_is_not_running_or_terminal_and_transport_stays_held(){if isolated("late_101_is_not_running_or_terminal_and_transport_stays_held"){return;}cancellation_case(true);}

#[test]fn running_witness_closes_transport_even_when_fake_pid0_refuses_cleanup(){
    if isolated("running_witness_closes_transport_even_when_fake_pid0_refuses_cleanup"){return;}
    let fake=Fake::new(false);let cancel=SocketCancellation::default();let(_,stream)=exec_hijack(CID,&["sleep","60"],false,&cancel).unwrap();await_event(&fake.queued);cancel.cancel();drop(stream);assert!(fake.probe_open());event(&fake.release);
    fake.mode.store(1,Ordering::SeqCst);assert!(cancel.finish_execs().is_err());assert!(cancel.has_execs());await_event(&fake.ended);fake.mode.store(2,Ordering::SeqCst);assert!(cancel.finish_execs().unwrap());
}
#[test]fn active_stdin_eof_waits_for_running_without_cancelling_session(){
    if isolated("active_stdin_eof_waits_for_running_without_cancelling_session"){return;}
    let fake=Fake::new(true);let cancel=SocketCancellation::default();let(_,stream)=exec_hijack(CID,&["cat"],false,&cancel).unwrap();await_event(&fake.queued);
    assert!(!cancel.try_exec_stdin_eof(EID).unwrap());assert!(cancel.check().is_ok());assert!(fake.probe_open());event(&fake.release);
    fake.mode.store(1,Ordering::SeqCst);assert!(cancel.try_exec_stdin_eof(EID).unwrap());await_event(&fake.ended);assert!(cancel.check().is_ok());drop(stream);cancel.cancel();fake.mode.store(2,Ordering::SeqCst);assert!(cancel.finish_execs().unwrap());
}
#[test]fn ordinary_and_created_transports_close_immediately_and_do_not_accumulate(){
    for _ in 0..32{let cancel=SocketCancellation::default();let(a,mut b)=UnixStream::pair().unwrap();b.set_read_timeout(Some(Duration::from_secs(1))).unwrap();cancel.register(&a).unwrap();cancel.cancel();let mut byte=[0];assert_eq!(b.read(&mut byte).unwrap(),0);assert!(cancel.sockets.lock().unwrap().is_none());
        let cancel=SocketCancellation::default();let(a,mut b)=UnixStream::pair().unwrap();b.set_read_timeout(Some(Duration::from_secs(1))).unwrap();let r=cancel.register_exec(CID,EID,"c".repeat(32)).unwrap();cancel.register_exec_transport(&a,&r).unwrap();cancel.cancel();assert!(r.start.never_started());assert_eq!(b.read(&mut byte).unwrap(),0);assert!(cancel.sockets.lock().unwrap().is_none());assert!(cancel.finish_execs().unwrap());}
}
#[test]fn only_complete_bounded_101_tcp_upgrade_head_opens_stdin_barrier(){
    let valid=b"HTTP/1.1 101 UPGRADED\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n";assert!(exec_upgrade_head_valid(valid));
    for bad in [b"HTTP/1.1 400 Error\r\n\r\n".as_slice(),b"HTTP/1.1 200 OK\r\n\r\n",b"HTTP/1.1 101 UPGRADED\r\nUpgrade: wrong\r\nConnection: upgrade\r\n\r\n",b"HTTP/1.1 101 UPGRADED\r\nConnection: upgrade\r\nUpgrade: tcp\r\n",b"notHTTP\r\n\r\n"]{assert!(!exec_upgrade_head_valid(bad));}
    let mut oversized=valid.to_vec();oversized.splice(0..0,vec![b'x';8193]);assert!(!exec_upgrade_head_valid(&oversized));
}
#[test]fn disconnect_witness_never_turns_a_timeout_or_bytes_into_eof(){
    assert!(disconnected_read(&Ok(0)));
    for kind in [std::io::ErrorKind::ConnectionReset,std::io::ErrorKind::ConnectionAborted,std::io::ErrorKind::BrokenPipe,std::io::ErrorKind::UnexpectedEof]{assert!(disconnected_read(&Err(std::io::Error::from(kind))));}
    for kind in [std::io::ErrorKind::TimedOut,std::io::ErrorKind::WouldBlock,std::io::ErrorKind::Interrupted,std::io::ErrorKind::Other]{assert!(!disconnected_read(&Err(std::io::Error::from(kind))));}
    assert!(!disconnected_read(&Ok(1)));
}
