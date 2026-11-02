//! Exact Pod container/endpoint binding for lazy diagnostic forwarding.
//! TCP handshake may occur before the second check, but no application bytes
//! or backend pump may run until both fresh observations agree.
use crate::{docker,pod_access::Permit,pod_sessions::Lease,reconcile::DesiredWorld};
use serde_json::Value;
use std::sync::{Arc,RwLock};

#[derive(Clone,Debug,PartialEq,Eq)]
pub struct Binding {
    pub container_id:String,
    pub started_at:String,
    pub endpoint:String,
    pub network_id:String,
}

fn from_inspect(v:&Value,id:&str,port:u16,linux:bool)->Result<(docker::DockerContainer,Binding),String>{
    if v["Id"].as_str()!=Some(id)||v["State"]["Running"].as_bool()!=Some(true)||port==0
        || ["Paused","Restarting","Dead"].iter().any(|flag|v["State"][flag].as_bool()==Some(true)){
        return Err("pinned Pod container is absent or no longer running".into());
    }
    let started_at=v["State"]["StartedAt"].as_str().filter(|s|!s.is_empty()).ok_or("container incarnation unavailable")?.to_string();
    let labels=serde_json::from_value(v["Config"]["Labels"].clone()).map_err(|_|"runtime labels unavailable")?;
    let c=docker::DockerContainer{id:id.into(),names:vec![v["Name"].as_str().unwrap_or("").into()],
        image:v["Image"].as_str().unwrap_or("").into(),state:"running".into(),status:"running".into(),labels,ports:vec![]};
    let (endpoint,network_id)=if linux {
        let networks=v["NetworkSettings"]["Networks"].as_object().ok_or("Pod network unavailable")?;
        let namespace=c.labels.get(crate::store::LABEL_NAMESPACE).filter(|s|!s.is_empty()).ok_or("Pod namespace unavailable")?;
        // Never let an alphabetically earlier default/global bridge override
        // the namespace endpoint (or silently replace a missing one).
        let network=networks.get(&format!("rk-{namespace}")).ok_or("Pod namespace network unavailable")?;
        let choice=network["IPAddress"].as_str().filter(|ip|!ip.is_empty()).map(|ip|(network,ip))
            .or_else(||network["GlobalIPv6Address"].as_str().filter(|ip|!ip.is_empty()).map(|ip|(network,ip)))
            .ok_or("Pod has no current IP")?;
        let ip:std::net::IpAddr=choice.1.parse().map_err(|_|"invalid Pod IP")?;
        let network=choice.0["NetworkID"].as_str().filter(|s|!s.is_empty()).ok_or("Pod network identity unavailable")?;
        (std::net::SocketAddr::new(ip,port).to_string(),network.to_string())
    }else{
        let key=format!("{port}/tcp");
        let (mapped,host)=v["NetworkSettings"]["Ports"][&key].as_array().and_then(|entries|entries.iter().find_map(|entry|{
            let port=entry["HostPort"].as_str()?.parse::<u16>().ok().filter(|p|*p>0)?;
            // A port published ONLY on another host IP does not prove that
            // localhost:port is this container; never dial a different service.
            let host=entry["HostIp"].as_str()?;
            let loopback=match host {"0.0.0.0"|"127.0.0.1"=>"127.0.0.1","::"|"::1"=>"::1",_=>return None};
            Some((std::net::SocketAddr::new(loopback.parse().ok()?,port),host.to_string()))
        })).ok_or("Pod port has no verified loopback publication")?;
        (mapped.to_string(),format!("published:{host}"))
    };
    Ok((c,Binding{container_id:id.into(),started_at,endpoint,network_id}))
}

pub fn snapshot(world:&Arc<RwLock<DesiredWorld>>,permit:&Permit,port:u16)->Result<Binding,String>{
    let inspect=docker::inspect_pinned_container(&permit.container_id)?;
    let (container,binding)=from_inspect(&inspect,&permit.container_id,port,cfg!(target_os="linux"))?;
    let world=world.read().unwrap_or_else(|e|e.into_inner());
    if !permit.valid_runtime(&world,&container){return Err("Pod runtime or authorization changed".into());}
    Ok(binding)
}

async fn observed(world:&Arc<RwLock<DesiredWorld>>,permit:&Permit,port:u16,lease:&Lease)->Result<Binding,String>{
    let (world,permit,worker)=(world.clone(),permit.clone(),lease.hold());
    tokio::task::spawn_blocking(move||{let _worker=worker;snapshot(&world,&permit,port)})
        .await.map_err(|_|"Pod endpoint observation failed")?
}

pub async fn connect(world:&Arc<RwLock<DesiredWorld>>,permit:&Permit,port:u16,pinned:&Binding,lease:&Lease)->Result<tokio::net::TcpStream,String>{
    connect_with_checks(pinned,||observed(world,permit,port,lease),|endpoint|async move{
        // Preserve the existing connect behavior/timeout; do not send data here.
        tokio::net::TcpStream::connect(endpoint).await.map_err(|e|e.to_string())
    }).await
}

async fn connect_with_checks<T,O,OF,D,DF>(pinned:&Binding,mut observe:O,dial:D)->Result<T,String>
where O:FnMut()->OF,OF:std::future::Future<Output=Result<Binding,String>>,
      D:FnOnce(String)->DF,DF:std::future::Future<Output=Result<T,String>>{
    if observe().await?!=*pinned{return Err("pinned Pod endpoint changed before connect".into());}
    let tcp=dial(pinned.endpoint.clone()).await?;
    if observe().await?!=*pinned{
        drop(tcp);return Err("pinned Pod endpoint changed while connecting".into());
    }
    Ok(tcp)
}

#[cfg(test)] mod tests {
    use super::*;
    fn inspect(id:&str)->Value{serde_json::json!({"Id":id,"Name":"/p","Image":"test","Config":{"Labels":{"royak.namespace":"test"}},
        "State":{"Running":true,"StartedAt":"2026-10-30T00:00:00Z"},
        "NetworkSettings":{"Networks":{"rk-test":{"NetworkID":"network-one","IPAddress":"172.20.0.2"}}}})}
    #[test]fn exact_id_state_and_network_incarnation_are_required(){
        let id="a".repeat(64);let v=inspect(&id);let (_,before)=from_inspect(&v,&id,8080,true).unwrap();
        let mut changed=v.clone();changed["Id"]=serde_json::json!("b".repeat(64));
        assert!(from_inspect(&changed,&id,8080,true).is_err());
        changed=v.clone();changed["State"]["Running"]=serde_json::json!(false);
        assert!(from_inspect(&changed,&id,8080,true).is_err());
        changed=v.clone();changed["NetworkSettings"]["Networks"]["rk-test"]["NetworkID"]=serde_json::json!("network-two");
        assert_ne!(before,from_inspect(&changed,&id,8080,true).unwrap().1);
        changed=v.clone();changed["State"]["StartedAt"]=serde_json::json!("new-boot");
        assert_ne!(before,from_inspect(&changed,&id,8080,true).unwrap().1);
    }
    #[test]fn unavailable_and_malformed_addresses_do_not_fallback(){
        let id="a".repeat(64);let mut v=inspect(&id);
        v["NetworkSettings"]["Networks"]["rk-test"]["IPAddress"]=serde_json::json!("untrusted.example");
        assert!(from_inspect(&v,&id,8080,true).is_err());
        v["NetworkSettings"]["Networks"]=serde_json::json!({});
        assert!(from_inspect(&v,&id,8080,true).is_err());
    }
    #[test]fn namespace_network_is_required_and_wins_over_other_attached_networks(){
        let id="a".repeat(64);let mut v=inspect(&id);
        v["NetworkSettings"]["Networks"]["bridge"]=serde_json::json!({"NetworkID":"foreign-default","IPAddress":"172.17.0.2"});
        v["NetworkSettings"]["Networks"]["royak"]=serde_json::json!({"NetworkID":"global-network","IPAddress":"172.18.0.2"});
        let binding=from_inspect(&v,&id,8080,true).unwrap().1;
        assert_eq!(binding.endpoint,"172.20.0.2:8080");assert_eq!(binding.network_id,"network-one");
        v["NetworkSettings"]["Networks"].as_object_mut().unwrap().remove("rk-test");
        assert!(from_inspect(&v,&id,8080,true).is_err(),"no ordinary/global route fallback");
    }
    #[test]fn paused_restarting_or_dead_runtime_cannot_mint_an_endpoint(){
        let id="a".repeat(64);
        for flag in ["Paused","Restarting","Dead"]{
            let mut v=inspect(&id);v["State"][flag]=serde_json::json!(true);
            assert!(from_inspect(&v,&id,8080,true).is_err());
        }
    }
    #[test]fn loopback_publication_must_cover_the_actual_dial_address(){
        let id="a".repeat(64);let mut v=inspect(&id);
        v["NetworkSettings"]["Ports"]=serde_json::json!({"8080/tcp":[{"HostIp":"192.0.2.5","HostPort":"40123"}]});
        assert!(from_inspect(&v,&id,8080,false).is_err());
        v["NetworkSettings"]["Ports"]["8080/tcp"][0]["HostIp"]=serde_json::json!("0.0.0.0");
        assert_eq!(from_inspect(&v,&id,8080,false).unwrap().1.endpoint,"127.0.0.1:40123");
        v["NetworkSettings"]["Ports"]["8080/tcp"][0]["HostIp"]=serde_json::json!("::1");
        assert_eq!(from_inspect(&v,&id,8080,false).unwrap().1.endpoint,"[::1]:40123");
    }
    #[tokio::test]async fn stale_before_connect_never_even_dials(){
        let id="a".repeat(64);let (_,pin)=from_inspect(&inspect(&id),&id,8080,true).unwrap();
        let mut stale=pin.clone();stale.container_id="b".repeat(64);
        let dialled=std::sync::atomic::AtomicBool::new(false);
        let result=connect_with_checks(&pin,||std::future::ready(Ok(stale.clone())),|_|{
            dialled.store(true,std::sync::atomic::Ordering::SeqCst);std::future::ready(Ok(()))
        }).await;
        assert!(result.is_err());assert!(!dialled.load(std::sync::atomic::Ordering::SeqCst));
    }
    #[tokio::test]async fn stale_after_dial_drops_socket_before_exposing_it_for_bytes(){
        let id="a".repeat(64);let (_,pin)=from_inspect(&inspect(&id),&id,8080,true).unwrap();
        let mut stale=pin.clone();stale.started_at="replacement".into();
        let mut observations=std::collections::VecDeque::from([pin.clone(),stale]);
        struct FakeSocket(Arc<std::sync::atomic::AtomicBool>);
        impl Drop for FakeSocket{fn drop(&mut self){self.0.store(true,std::sync::atomic::Ordering::SeqCst);}}
        let dropped=Arc::new(std::sync::atomic::AtomicBool::new(false));
        let result=connect_with_checks(&pin,||std::future::ready(Ok(observations.pop_front().unwrap())),|_|{
            std::future::ready(Ok(FakeSocket(dropped.clone())))
        }).await;
        assert!(result.is_err());assert!(dropped.load(std::sync::atomic::Ordering::SeqCst));
        assert!(observations.is_empty());
    }
    #[tokio::test]async fn unchanged_identity_reaches_both_checks_then_returns_socket(){
        let id="a".repeat(64);let (_,pin)=from_inspect(&inspect(&id),&id,8080,true).unwrap();
        let observations=std::sync::atomic::AtomicUsize::new(0);
        let result=connect_with_checks(&pin,||{observations.fetch_add(1,std::sync::atomic::Ordering::SeqCst);std::future::ready(Ok(pin.clone()))},|_|std::future::ready(Ok(7))).await;
        assert_eq!(result.unwrap(),7);assert_eq!(observations.load(std::sync::atomic::Ordering::SeqCst),2);
    }
}
