//! Private Unix-socket fake, never Docker or real process signals. On Linux
//! the copied root-private dockerd-named test process is the actual SCM sender.
//! The original delayed-start/null/Running/numeric-terminal semantics survive.
use super::*;
use std::sync::{Arc,Mutex,Condvar,atomic::{AtomicBool,AtomicUsize,Ordering}};
use std::os::unix::{net::UnixListener,fs::PermissionsExt};
#[path="exec_fixture.rs"]
mod fixture;
const CONTAINER:&str="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const EXEC:&str="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
fn isolated(name:&str)->bool{
    fixture::isolated(module_path!(),name,"ROYAK_EXEC_START_RACE_ISOLATED",
        name!="missing_exec_with_live_container_is_not_terminal_proof")
}
struct Fake {
    dir:std::path::PathBuf,
    previous:Option<String>,
    stop:Arc<AtomicBool>,
    queued:Arc<(Mutex<bool>,Condvar)>,
    release:Arc<(Mutex<bool>,Condvar)>,
    mode:Arc<AtomicUsize>, // 0 created/null; 1 running; 2 done/0; 3 exec404/live; 4 both404
    server:Option<std::thread::JoinHandle<()>>,
    workers:Arc<Mutex<Vec<std::thread::JoinHandle<()>>>>,
    _journal:fixture::JournalScope,
}
fn reply(s:&mut UnixStream,status:u16,body:&str){
    let value=format!("HTTP/1.1 {status} TEST\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len());
    let _=s.write_all(value.as_bytes());
}
impl Fake {
    fn new()->Self{
        let mut journal=fixture::JournalScope::new();
        let dir=std::fs::canonicalize("/tmp").unwrap().join(format!("rke-{}",crate::storage_identity::Uid::new().as_str()));
        std::fs::create_dir(&dir).unwrap();std::fs::set_permissions(&dir,std::fs::Permissions::from_mode(0o700)).unwrap();
        let path=dir.join("docker.sock");let listener=UnixListener::bind(&path).unwrap();listener.set_nonblocking(true).unwrap();
        std::fs::set_permissions(&path,std::fs::Permissions::from_mode(0o600)).unwrap();
        journal.pin_socket(&path);
        let stop=Arc::new(AtomicBool::new(false));let queued=Arc::new((Mutex::new(false),Condvar::new()));
        let release=Arc::new((Mutex::new(false),Condvar::new()));let mode=Arc::new(AtomicUsize::new(0));
        let created=Arc::new(AtomicBool::new(false));
        let workers=Arc::new(Mutex::new(vec![]));
        let (st,q,rel,m,ws)=(stop.clone(),queued.clone(),release.clone(),mode.clone(),workers.clone());
        let server=std::thread::spawn(move||{
            while !st.load(Ordering::SeqCst){
                match listener.accept(){
                    Ok((mut socket,_))=>{
                        let (q,rel,m,created)=(q.clone(),rel.clone(),m.clone(),created.clone());
                        ws.lock().unwrap().push(std::thread::spawn(move||{
                            socket.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
                            let mut attested=false;
                            while let Some((first,body))=fixture::request(&mut socket){
                                if first=="GET /info HTTP/1.1"{
                                    assert!(!attested,"only one Info preflight per connection");
                                    fixture::info(&mut socket);attested=true;continue;
                                }
                                if first=="GET /containers/json?all=1 HTTP/1.1"{
                                    assert!(attested,"startup census must use actual sender attestation");
                                    reply(&mut socket,200,&format!(r#"[{{"Id":"{CONTAINER}","Labels":{{"royak.cluster":"aabbccddeeff","royak.node":"fixture"}}}}]"#));
                                }else if first==format!("POST /containers/{CONTAINER}/exec HTTP/1.1"){
                                    assert!(attested,"Create must reuse the Info-attested socket");
                                    let request:serde_json::Value=serde_json::from_slice(&body).unwrap();
                                    assert_eq!(request["Env"].as_array().unwrap().len(),1);
                                    assert!(!created.swap(true,Ordering::SeqCst),"Create is one-shot");
                                    reply(&mut socket,201,&format!(r#"{{"Id":"{EXEC}"}}"#));
                                }else if first==format!("POST /exec/{EXEC}/start HTTP/1.1"){
                                    assert!(attested,"Start must reuse the Info-attested socket");
                                    // Exact Moby order: upgrade precedes ContainerExecStart.
                                    let _=socket.write_all(b"HTTP/1.1 101 UPGRADED\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n");
                                    {let (lock,cv)=&*q;*lock.lock().unwrap()=true;cv.notify_all();}
                                    let (lock,cv)=&*rel;let guard=lock.lock().unwrap();
                                    let _guard=cv.wait_while(guard,|ready|!*ready).unwrap();
                                    m.store(1,Ordering::SeqCst);cv.notify_all();
                                }else if first==format!("GET /exec/{EXEC}/json HTTP/1.1"){
                                    let state=m.load(Ordering::SeqCst);
                                    if state>=3 {reply(&mut socket,404,r#"{"message":"not found"}"#);}
                                    else {let running=state==1;let exit=if state==2{"0"}else{"null"};
                                        reply(&mut socket,200,&format!(r#"{{"ID":"{EXEC}","ContainerID":"{CONTAINER}","Running":{running},"ExitCode":{exit},"Pid":0}}"#));}
                                }else if first==format!("GET /containers/{CONTAINER}/json HTTP/1.1"){
                                    if m.load(Ordering::SeqCst)==4{reply(&mut socket,404,r#"{"message":"not found"}"#);}
                                    else {let execs=if created.load(Ordering::SeqCst){format!(r#"["{EXEC}"]"#)}else{"null".into()};
                                        reply(&mut socket,200,&format!(r#"{{"Id":"{CONTAINER}","ExecIDs":{execs}}}"#));}
                                }else{panic!("unexpected fake request {first}");}
                                // Every non-Info response closes its HTTP connection.
                                break;
                            }
                        }));
                    },
                    Err(e) if e.kind()==std::io::ErrorKind::WouldBlock=>std::thread::sleep(Duration::from_millis(1)),
                    Err(e)=>panic!("fake accept: {e}"),
                }
            }
        });
        let previous=std::env::var("DOCKER_HOST").ok();std::env::set_var("DOCKER_HOST",format!("unix://{}",path.display()));
        journal.start_agent();
        Self{dir,previous,stop,queued,release,mode,server:Some(server),workers,_journal:journal}
    }
    fn queued(&self){let (lock,cv)=&*self.queued;let guard=lock.lock().unwrap();let (guard,t)=cv.wait_timeout_while(guard,Duration::from_secs(2),|v|!*v).unwrap();assert!(*guard&&!t.timed_out(),"start request never queued");}
    fn commit(&self){let (lock,cv)=&*self.release;*lock.lock().unwrap()=true;cv.notify_all();}
    fn committed(&self){let (lock,cv)=&*self.release;let guard=lock.lock().unwrap();let (_guard,timeout)=cv.wait_timeout_while(guard,Duration::from_secs(2),|_|self.mode.load(Ordering::SeqCst)!=1).unwrap();assert!(!timeout.timed_out(),"fake daemon failed to commit queued start");}
}
impl Drop for Fake {
    fn drop(&mut self){
        self._journal.stop_agent();
        self.commit();self.stop.store(true,Ordering::SeqCst);
        let mut failed=false;
        if let Some(s)=self.server.take(){failed|=s.join().is_err();}
        for w in self.workers.lock().unwrap_or_else(|e|e.into_inner()).drain(..){failed|=w.join().is_err();}
        if let Some(v)=self.previous.take(){std::env::set_var("DOCKER_HOST",v);}else{std::env::remove_var("DOCKER_HOST");}
        fixture::cleanup(std::fs::remove_file(self.dir.join("docker.sock")),"exact fake socket");
        fixture::cleanup(std::fs::remove_dir(&self.dir),"exact fake directory");
        if failed {fixture::cleanup(Err(std::io::Error::other("fake worker panicked")),"fake workers");}
    }
}
#[test]
fn delayed_start_after_upgrade_keeps_its_reference_until_numeric_terminal_witness(){
    if isolated("delayed_start_after_upgrade_keeps_its_reference_until_numeric_terminal_witness"){return;}
    let fake=Fake::new();let cancel=Arc::new(SocketCancellation::default());let worker_cancel=cancel.clone();
    let worker=std::thread::spawn(move||exec_hijack(CONTAINER,&["cat"],false,&worker_cancel));
    fake.queued();cancel.cancel();
    let prematurely_finished=cancel.finish_execs().unwrap();
    fake.commit();fake.committed();let _=worker.join().unwrap();
    let late_running=cancel.finish_execs();
    let late_reference_retained=cancel.has_execs();
    fake.mode.store(2,Ordering::SeqCst);
    assert!(cancel.finish_execs().unwrap(),"numeric terminal result should permit release");
    assert!(!prematurely_finished,"baseline bug: Running=false + ExitCode=null retired a queued start after 101");
    assert!(late_running.is_err()&&late_reference_retained,"late Running must remain tracked; fake Pid0 must refuse any signal");
}
#[test]
fn missing_exec_with_live_container_is_not_terminal_proof(){
    if isolated("missing_exec_with_live_container_is_not_terminal_proof"){return;}
    let fake=Fake::new();let cancel=SocketCancellation::default();
    let _=cancel.register_exec(CONTAINER,EXEC,"c".repeat(32)).unwrap();
    fake.mode.store(3,Ordering::SeqCst);
    assert!(cancel.finish_execs().is_err());
    fake.mode.store(4,Ordering::SeqCst);
    assert!(cancel.finish_execs().unwrap());
}

#[test]
fn closed_startup_gate_refuses_all_four_create_paths_without_io() {
    if fixture::isolated(module_path!(),"closed_startup_gate_refuses_all_four_create_paths_without_io",
        "ROYAK_EXEC_CLOSED_GATE_ISOLATED",false) { return; }
    assert!(!diagnostic_recovery_ready());
    let usage=diagnostic_recovery_usage();
    assert_ne!(usage["state"],"Ready");
    assert!(usage["unattributed_possible_running"].is_null());
    let dir=std::fs::canonicalize("/tmp").unwrap().join(format!("rkg-{}",crate::storage_identity::Uid::new().as_str()));
    std::fs::create_dir(&dir).unwrap();
    std::fs::set_permissions(&dir,std::fs::Permissions::from_mode(0o700)).unwrap();
    let path=dir.join("unused.sock");let listener=UnixListener::bind(&path).unwrap();
    listener.set_nonblocking(true).unwrap();
    std::env::set_var("DOCKER_HOST",format!("unix://{}",path.display()));
    let cancel=SocketCancellation::default();
    let errors=[
        exec_hijack(CONTAINER,&["cat"],false,&cancel).err().unwrap(),
        exec_capture(CONTAINER,&["true"],&cancel).err().unwrap(),
        exec_in_container(CONTAINER,&["true"]).err().unwrap(),
        probe_exec(CONTAINER,&["true"],Duration::from_secs(1)).err().unwrap(),
    ];
    for error in errors { assert!(exec_admission_unknown(&error),"{error}"); }
    assert!(!cancel.has_execs());
    assert!(matches!(listener.accept(),Err(e) if e.kind()==std::io::ErrorKind::WouldBlock),
        "Closed gate must refuse even GET/Info; no hidden handler census");
    assert!(crate::pod_sessions::admit("unattributed").is_err());
    let quotas=crate::pod_sessions::usage();
    assert!(quotas["active_or_closing"].is_null() && quotas["users"].is_null());
    assert_eq!(quotas["current_process_active_or_closing"],0);
    std::env::remove_var("DOCKER_HOST");drop(listener);
    std::fs::remove_file(path).unwrap();std::fs::remove_dir(dir).unwrap();
}
