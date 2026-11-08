//! Bounded readonly whole-pool reference census. Only an actual inherited v7
//! context can represent managed references; no PID/path/minor allowlist.
use super::*;
use crate::storage_driver::dispatcher::attachment::inventory::{InheritedOwnedPoolInventory,InventoryOperation};
use std::collections::{BTreeMap,BTreeSet};
// SAME reviewed anchor bounds, not new worker/resource/capacity allowances.
const MAX_TASKS:usize=16384;const MAX_FDS:usize=4096;const MAX_TOTAL_FDS:usize=65536;
const MAX_NAMESPACES:usize=64;const MAX_MOUNTINFO_BYTES:usize=4*1024*1024;
#[cfg(not(target_os="linux"))]
pub(in crate::storage_driver) fn inspect(_:&InheritedOwnedPoolInventory,_:&BTreeSet<(u32,u32)>)->Result<(),String>{Err("owned inventory reference census requires Linux".into())}
#[cfg(target_os="linux")]
pub(in crate::storage_driver) fn inspect(context:&InheritedOwnedPoolInventory,devices:&BTreeSet<(u32,u32)>)->Result<(),String>{
    use std::os::unix::fs::FileTypeExt;
    context.before_inventory(InventoryOperation::KernelCensus)?;
    // Every observed namespace remains actually pinned during the census.
    // 64 namespace roots +12 maximum simultaneously-live observer/iterator
    // descriptors in the lexical task path; actual inherited23 already count.
    terminal::origin::require_descriptor_headroom((MAX_NAMESPACES+12)as u64)?;
    let boot=crate::storage_boot::BootId::current()?;let own=open_current_namespace()?;
    if fd_identity(&own)?!=context.table().namespace{return Err("inventory helper not in same original Watch namespace".into());}
    let proc=File::open("/proc").map_err(|_|"actual inventory proc root unavailable")?;anchor::require_fs(&proc,0x9fa0)?;
    let mut namespaces:BTreeMap<(u64,u64),(File,String)>=BTreeMap::new();let mut referenced=BTreeSet::new();
    let mut tasks=0usize;let mut descriptors=0usize;let mut graph_bytes=0usize;
    let mut seen_watch=BTreeSet::new();let mut seen_helper=BTreeSet::new();
    context.reobserve_members()?;
    for pid in anchor::inventory_entries(&proc,MAX_TASKS)?{
        let Some(tgid)=anchor::inventory_decimal(&pid)else{continue;};
        let process=anchor::open_directory_at(&proc,&pid)?;let threads=anchor::open_directory_at(&process,"task")?;
        for name in anchor::inventory_entries(&threads,MAX_TASKS)?{
            if Instant::now()>=context.deadline()||tasks>=MAX_TASKS{return Err("inventory original deadline/task bound exhausted".into());}
            let tid=anchor::inventory_decimal(&name).ok_or("invalid actual task TID")?;tasks+=1;
            let task=anchor::open_directory_at(&threads,&name)?;
            let before=anchor::terminal_task_stamp(&anchor::read_at(&task,"stat",4096)?,&anchor::read_at(&task,"status",65536)?,tgid,tid)?;
            let namespace=anchor::open_namespace_at(&task)?;let identity=fd_identity(&namespace)?;
            let graph=anchor::read_at(&task,"mountinfo",1024*1024)?;let graph_sha=hash(&graph);
            if let Some((_,prior))=namespaces.get(&identity){if prior!=&graph_sha{return Err("actual namespace graph changed during inventory".into());}}
            else{
                graph_bytes=graph_bytes.checked_add(graph.len()).ok_or("inventory graph byte overflow")?;
                if namespaces.len()>=MAX_NAMESPACES||graph_bytes>MAX_MOUNTINFO_BYTES{return Err("inventory namespace/total graph bounds exhausted".into());}
                let raw=std::str::from_utf8(&graph).map_err(|_|"actual inventory mountinfo encoding")?;
                let rows=super::super::parse_mounts(raw)?;
                for row in rows.iter().filter(|r|devices.contains(&(r.major,r.minor))){
                    let matching=context.table().members.iter().filter(|member|{let m=&member.observation.mounted;
                        identity==context.table().namespace&&m.mount_id==row.id&&m.target==row.target
                            &&(m.device_major,m.device_minor)==(row.major,row.minor)&&row.filesystem=="ext4"&&row.root=="/"&&row.optional.is_empty()}).count();
                    if matching!=1||row.target=="/"{return Err("foreign/unclassified/aliased/root pool mount in actual namespace graph".into());}
                }
                namespaces.insert(identity,(namespace.try_clone().map_err(|_|"cannot continuously pin actual census namespace")?,graph_sha));
            }
            let fds=anchor::open_directory_at(&task,"fd")?;
            let count=anchor::walk_fd_names(&fds,MAX_FDS,|number|{
                if Instant::now()>=context.deadline()||descriptors>=MAX_TOTAL_FDS{return Err("inventory actual FD/deadline bound exhausted".into());}descriptors+=1;
                let link=anchor::inventory_read_link(&fds,number)?;if let Some(inode)=anchor::inventory_namespace_link(&link)?{referenced.insert(inode);}
                let n=number.parse::<i32>().map_err(|_|"inventory descriptor number overflow")?;
                let potential=context.potential_reference(tgid,n);
                if potential{context.verify_represented_table(tgid,tid,identity)?;}
                let m=std::fs::metadata(format!("/proc/self/fd/{}/{}",fds.as_raw_fd(),number)).map_err(|_|"actual task FD changed/unavailable; UNKNOWN")?;
                let storage=devices.iter().any(|(a,b)|m.dev()==libc::makedev(*a,*b)||m.file_type().is_block_device()&&m.rdev()==libc::makedev(*a,*b));
                if potential&&!storage{return Err("represented original slot changed from exact pool storage File".into());}
                if storage{
                    if !potential{return Err("unclassified actual pool reference remains; no PID/path/minor exemption".into());}
                    if !context.represented_reference(tgid,n,&m)?{return Err("unclassified pool filesystem/block reference remains".into());}
                    context.verify_represented_table(tgid,tid,identity)?;
                    // Require each exact original and duplicate in the pinned
                    // leader's real table, not a summary or thread assumption.
                    if tid==tgid{if tgid==context.table().watch.pid(){seen_watch.insert(n);}else if tgid==std::process::id(){seen_helper.insert(n);}}
                }Ok(())
            })?;
            let mut absent=0;
            for name in ["root","cwd"]{match std::fs::metadata(format!("/proc/self/fd/{}/{name}",task.as_raw_fd())){
                Ok(m)=>{if devices.iter().any(|(a,b)|m.dev()==libc::makedev(*a,*b)){return Err("actual task root/cwd references pool filesystem".into());}},
                Err(e)if e.raw_os_error()==Some(libc::ENOENT)&&before.kthread&&count==0=>absent+=1,
                Err(_)=>return Err("user/unknown task root/cwd unavailable; no absence inference".into()),
            }}
            let after=anchor::terminal_task_stamp(&anchor::read_at(&task,"stat",4096)?,&anchor::read_at(&task,"status",65536)?,tgid,tid)?;
            let after_ns=anchor::open_namespace_at(&task)?;
            if before!=after||fd_identity(&after_ns)?!=identity||anchor::read_at(&task,"mountinfo",1024*1024)?!=graph{
                return Err("actual inventory task/namespace/graph incarnation changed".into());}
            if absent>0&&(!after.kthread||anchor::walk_fd_names(&fds,MAX_FDS,|_|Err("kernel task acquired an actual FD".into()))?!=0){
                return Err("actual empty kernel task classification changed".into());}
        }
    }
    if referenced.iter().any(|id|!namespaces.keys().any(|(_,inode)|inode==id)){
        return Err("unrepresented namespace FD; dedicated scope does not prove universal hidden-namespace absence".into());}
    for member in &context.table().members{
        for number in [member.observation.original_mounted.number,member.observation.original_block.number,member.mounted_fd,member.block_fd]{
            if !seen_watch.contains(&number){return Err("exact original Watch reference missing from stable leader census".into());}}
        for number in [member.mounted_fd,member.block_fd]{if !seen_helper.contains(&number){return Err("exact inherited helper reference missing from stable leader census".into());}}
    }
    context.reobserve_members()?;
    if crate::storage_boot::BootId::current()?!=boot||fd_identity(&open_current_namespace()?)?!=context.table().namespace{
        return Err("inventory boot/current namespace changed".into());}
    context.before_inventory(InventoryOperation::KernelCensus)
}
