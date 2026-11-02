//! Profile7-only pool observation. Old inspect/unmounted_tree are unchanged.
//! Entire original --tree reports are classified, never filtered/nullified.
use super::*;
use crate::storage_driver::dispatcher::attachment::inventory::{InheritedOwnedPoolInventory,InventoryOperation};
use std::os::unix::fs::{MetadataExt,FileTypeExt};
use std::os::fd::AsRawFd;
use std::collections::BTreeMap;
fn owned_command(inventory:&InheritedOwnedPoolInventory,program:Program,args:&[&str])->Result<Value,String>{
    let operation=match program{Program::Pvs=>InventoryOperation::Pvs,Program::Vgs=>InventoryOperation::Vgs,
        Program::Lvs=>InventoryOperation::Lvs,Program::Lsblk=>InventoryOperation::Lsblk,_=>return Err("not a closed owned inventory program".into())};
    if args!=operation.args(){return Err("owned inventory actual argv differs from fixed source vector".into());}
    inventory.before_inventory(operation)?;
    let value=command(program,args)?;
    inventory.before_inventory(operation)?;Ok(value)
}
#[derive(Clone,Debug,PartialEq,Eq)]
struct KernelRelations {holders:BTreeSet<(u32,u32)>,slaves:BTreeSet<(u32,u32)>}
#[cfg(target_os="linux")]
fn kernel_node(id:(u32,u32))->Result<std::path::PathBuf,String>{
    let root=std::path::Path::new("/sys/devices");
    let path=std::fs::canonicalize(format!("/sys/dev/block/{}:{}",id.0,id.1)).map_err(|_|"actual sysfs pool block identity absent")?;
    if !path.starts_with(root){return Err("actual sysfs block resolves outside kernel devices".into());}
    let file=std::fs::File::open(&path).map_err(|_|"actual sysfs block directory unavailable")?;
    super::super::replica::initialize::managed_mount::anchor::require_fs(&file,0x62656572)?;
    let raw=super::super::replica::initialize::managed_mount::anchor::read_at(&file,"dev",64)?;
    if std::str::from_utf8(&raw).map_err(|_|"sysfs dev encoding")?.trim()!=format!("{}:{}",id.0,id.1){return Err("sysfs block dev identity changed".into());}
    Ok(path)
}
#[cfg(target_os="linux")]
fn relations(id:(u32,u32))->Result<KernelRelations,String>{
    let path=kernel_node(id)?;
    let mut read=|kind:&str|->Result<BTreeSet<(u32,u32)>,String>{
        let mut values=BTreeSet::new();let dir=path.join(kind);
        for entry in std::fs::read_dir(&dir).map_err(|_|"actual sysfs holders/slaves unavailable")?{
            if values.len()>=4096{return Err("actual sysfs edge count exceeds original per-directory4096 bound".into());}
            let entry=entry.map_err(|_|"sysfs edge enumeration UNKNOWN")?;
            let child=std::fs::canonicalize(entry.path()).map_err(|_|"actual sysfs edge disappeared")?;
            if !child.starts_with("/sys/devices"){return Err("sysfs edge escaped actual kernel devices".into());}
            let file=std::fs::File::open(&child).map_err(|_|"actual sysfs edge directory unavailable")?;
            super::super::replica::initialize::managed_mount::anchor::require_fs(&file,0x62656572)?;
            let raw=super::super::replica::initialize::managed_mount::anchor::read_at(&file,"dev",64)?;
            let text=std::str::from_utf8(&raw).map_err(|_|"actual sysfs edge dev encoding")?.trim();
            let(a,b)=text.split_once(':').ok_or("actual sysfs edge dev malformed")?;
            let key=(a.parse::<u32>().map_err(|_|"sysfs major overflow")?,b.parse::<u32>().map_err(|_|"sysfs minor overflow")?);
            if kernel_node(key)?!=child||!values.insert(key){return Err("ambiguous/aliased actual sysfs edge".into());}
        }Ok(values)
    };
    Ok(KernelRelations{holders:read("holders")?,slaves:read("slaves")?})
}
#[cfg(target_os="linux")]
fn actual_block(path:&str)->Result<(u32,u32),String>{
    use std::os::unix::fs::OpenOptionsExt;
    let resolved=std::fs::canonicalize(path).map_err(|_|"actual raw inventory block path absent")?;
    if !resolved.starts_with("/dev")||resolved.components().count()!=3{return Err("inventory block is not a canonical direct dev leaf".into());}
    let file=std::fs::OpenOptions::new().read(true).custom_flags(libc::O_PATH|libc::O_CLOEXEC|libc::O_NOFOLLOW).open(&resolved)
        .map_err(|_|"actual inventory block FD unavailable")?;
    let m=file.metadata().map_err(|_|"actual inventory block FD metadata unavailable")?;
    if !m.file_type().is_block_device(){return Err("inventory path is not an actual kernel block node".into());}
    let id=(libc::major(m.rdev())as u32,libc::minor(m.rdev())as u32);kernel_node(id)?;Ok(id)
}
impl InheritedOwnedPoolInventory {
    #[cfg(not(target_os="linux"))]
    pub(in crate::storage_driver) fn validate_pool_tree(&self,_:&Config,_:&Value,_:&Pool)->Result<(),String>{Err("owned pool graph requires Linux".into())}
    #[cfg(target_os="linux")]
    pub(in crate::storage_driver) fn validate_pool_tree(&self,cfg:&Config,selected:&Value,pool:&Pool)->Result<(),String>{
        self.before_inventory(InventoryOperation::KernelCensus)?;
        cfg.validate()?;let target=self.scope().target()?;
        if cfg.node_uid!=self.scope().phase_node_uid||cfg.pool_uid!=target.pool_uid||cfg.cluster_id!=self.scope().owner.cluster_id
            ||self.table().live_members.iter().any(|f|f.pool_uid!=cfg.pool_uid||f.node_uid!=cfg.node_uid){return Err("whole-pool inventory current source/pool differs".into());}
        let mut backing=BTreeSet::new();let mut active=BTreeSet::new();
        let dir=Dir::open(&cfg.journal_path(),false)?;
        for fact in &self.table().live_members{
            fact.validate()?;let record=load(&dir,&fact.volume_uid)?.ok_or("actual same-book allocation absent")?;validate_record(cfg,&record)?;
            let lv=owned_lv(pool,cfg,&record)?.ok_or("actual same-book owned thick LV absent")?;
            if record.stage!=Stage::Prepared||record.allocation_nonce!=fact.allocation_nonce||record.request.operation_uid!=fact.prepare_operation_uid
                ||record.request.capacity_bytes!=fact.requested_bytes||lv.uuid!=fact.lv_uuid{return Err("same-book protected allocation/tag/LV incarnation differs".into());}
            let key=(u32::try_from(lv.major).map_err(|_|"actual LV major overflow")?,u32::try_from(lv.minor).map_err(|_|"actual LV minor overflow")?);
            if !backing.insert(key){return Err("same-book volumes alias one backing block".into());}
            let minor=super::super::replica::initialized_activation::inventory_minor(cfg,fact)?;
            if !active.insert((147,minor)){return Err("same-book DRBD block aliases another volume".into());}
            if let Some(member)=self.table().members.iter().find(|m|m.observation.fact==*fact){
                if (member.observation.mounted.device_major,member.observation.mounted.device_minor)!=(147,minor){return Err("actual original mounted owner differs from retained exact plan".into());}
            }
        }
        let mut nodes=BTreeMap::new();let mut edges=BTreeSet::new();
        fn walk<'a>(node:&'a Value,parent:Option<(u32,u32)>,nodes:&mut BTreeMap<(u32,u32),&'a Value>,edges:&mut BTreeSet<((u32,u32),(u32,u32))>)->Result<(),String>{
            if nodes.len()>=4096{return Err("actual raw block tree exceeds original4096 directory bound".into());}
            let key=actual_block(field(node,"path")?)?;
            if nodes.insert(key,node).is_some(){return Err("raw block tree repeats/aliases actual kernel block identity".into());}
            if let Some(parent)=parent{edges.insert((parent,key));}
            if let Some(children)=node.get("children"){for child in children.as_array().ok_or("invalid original raw block children")?{walk(child,Some(key),nodes,edges)?;}}Ok(())
        }
        walk(selected,None,&mut nodes,&mut edges)?;let physical=actual_block(field(selected,"path")?)?;
        let mut kernel=BTreeMap::new();
        for(key,node)in &nodes{
            if *key!=physical&&!backing.contains(key)&&!active.contains(key){return Err("unclassified/foreign actual pool descendant".into());}
            let links=relations(*key)?;
            for child in &links.holders{if !nodes.contains_key(child)||!edges.contains(&(*key,*child)){return Err("kernel holder missing from full explicit raw tree".into());}}
            if *key!=physical{for slave in &links.slaves{if !nodes.contains_key(slave)||!edges.contains(&(*slave,*key)){return Err("foreign/aliased kernel slave in pool descendant".into());}}}
            let mounts=node.get("mountpoints").and_then(Value::as_array).ok_or("raw block mountpoints missing")?;
            for mount in mounts.iter().filter(|v|!v.is_null()&&v.as_str()!=Some("")){
                let matching=self.table().members.iter().filter(|m|{let x=&m.observation.mounted;
                    (x.device_major,x.device_minor)==*key&&mount.as_str()==Some(x.target.as_str())&&x.target!="/"}).count();
                if matching!=1{return Err("foreign/unclassified/root/swap mount in whole original pool graph".into());}
            }
            kernel.insert(*key,links);
        }
        for(parent,child)in &edges{if !kernel[parent].holders.contains(child)||!kernel[child].slaves.contains(parent){
            return Err("original raw hierarchy lacks exact reciprocal kernel holder/slave edges".into());}}
        for member in &self.table().members{let key=(member.observation.mounted.device_major,member.observation.mounted.device_minor);
            let node=nodes.get(&key).ok_or("genuine mounted member missing from whole original raw pool graph")?;
            if node.get("mountpoints").and_then(Value::as_array).is_none_or(|v|v.iter().filter(|p|p.as_str()==Some(member.observation.mounted.target.as_str())).count()!=1){
                return Err("raw tree did not observe exact genuine mounted target once".into());}}
        let devices=nodes.keys().copied().collect();
        super::super::replica::initialize::managed_mount::inventory::census::inspect(self,&devices)?;
        for(key,prior)in kernel{if relations(key)?!=prior{return Err("actual kernel pool graph changed across census".into());}}
        self.before_inventory(InventoryOperation::KernelCensus)
    }
}
fn validate_inventory_owned(
    inventory:&InheritedOwnedPoolInventory,
    cfg: &Config,
    pvs: &Value,
    vgs: &Value,
    lvs: &Value,
    blocks: &Value,
    boot_id: String,
) -> Result<Pool, String> {
    let vgrows = rows(vgs, "vg")?;
    let pvs = rows(pvs, "pv")?;
    let vg: Vec<_> = vgrows
        .iter()
        .filter(|r| field(r, "vg_name").ok() == Some(cfg.vg_name.as_str()))
        .collect();
    if vg.len() != 1 || field(vg[0], "vg_uuid")? != cfg.vg_uuid {
        return Err("VG name/UUID is missing, changed or ambiguous".into());
    }
    let pv: Vec<_> = pvs
        .iter()
        .filter(|r| field(r, "vg_uuid").ok() == Some(cfg.vg_uuid.as_str()))
        .collect();
    if pv.len() != 1
        || field(pv[0], "pv_uuid")? != cfg.pv_uuid
        || field(pv[0], "vg_name")? != cfg.vg_name
    {
        return Err("pool is not the exact approved single-PV volume group".into());
    }
    let disk_path = field(pv[0], "pv_name")?.to_string();
    let mut devices = Vec::new();
    flatten(
        blocks
            .get("blockdevices")
            .and_then(Value::as_array)
            .ok_or("missing block inventory")?,
        &mut devices,
    )?;
    let disks: Vec<_> = devices
        .into_iter()
        .filter(|d| {
            d.get("type").and_then(Value::as_str) == Some("disk")
                && d.get("serial").and_then(Value::as_str).map(str::trim)
                    == Some(cfg.disk_serial.as_str())
        })
        .collect();
    if disks.len() != 1 || field(disks[0], "path")? != disk_path {
        return Err("physical disk serial/path does not match the approved PV".into());
    }
    let size = number(field(vg[0], "vg_size")?)?;
    let free = number(field(vg[0], "vg_free")?)?;
    let extent = number(field(vg[0], "vg_extent_size")?)?;
    if size == 0 || free > size || extent == 0 || extent % 4096 != 0 {
        return Err("invalid pool geometry".into());
    }
    let mut volumes = Vec::new();
    for r in rows(lvs, "lv")?
        .into_iter()
        .filter(|r| field(r, "vg_uuid").ok() == Some(cfg.vg_uuid.as_str()))
    {
        let major = field(&r, "lv_kernel_major")?;
        let minor = field(&r, "lv_kernel_minor")?;
        volumes.push(Lv {
            name: field(&r, "lv_name")?.into(),
            uuid: field(&r, "lv_uuid")?.into(),
            bytes: number(field(&r, "lv_size")?)?,
            tags: field(&r, "lv_tags")?
                .split(',')
                .filter(|t| !t.is_empty())
                .map(str::to_string)
                .collect(),
            attr: field(&r, "lv_attr")?.into(),
            segtype: field(&r, "segtype")?.into(),
            major: if major == "-1" {
                u64::MAX
            } else {
                number(major)?
            },
            minor: if minor == "-1" {
                u64::MAX
            } else {
                number(minor)?
            },
        });
    }
    let pool=Pool {
        kind: "royak-approved-lvm-pool-v1",
        cluster_id: cfg.cluster_id.clone(),
        node_uid: cfg.node_uid.clone(),
        pool_uid: cfg.pool_uid.clone(),
        boot_id,
        disk_path,
        disk_serial: cfg.disk_serial.clone(),
        pv_uuid: cfg.pv_uuid.clone(),
        vg_name: cfg.vg_name.clone(),
        vg_uuid: cfg.vg_uuid.clone(),
        size_bytes: size,
        free_bytes: free,
        extent_bytes: extent,
        logical_volumes: volumes,
        drbd_module_version: None,
        pod_access_granted: false,
    };
    inventory.validate_pool_tree(cfg,disks[0],&pool)?;Ok(pool)
}

pub(in crate::storage_driver) fn inspect_owned(inventory:&InheritedOwnedPoolInventory,cfg:&Config) -> Result<Pool, String> {
    let pvs = owned_command(inventory,
        Program::Pvs,
        &[
            "--reportformat",
            "json",
            "--units",
            "b",
            "--nosuffix",
            "-o",
            "pv_name,pv_uuid,vg_name,vg_uuid",
        ],
    )?;
    let vgs = owned_command(inventory,
        Program::Vgs,
        &[
            "--reportformat",
            "json",
            "--units",
            "b",
            "--nosuffix",
            "-o",
            "vg_name,vg_uuid,vg_size,vg_free,vg_extent_size",
        ],
    )?;
    let lvs=owned_command(inventory,Program::Lvs,&["--reportformat","json","--units","b","--nosuffix","-o","vg_uuid,lv_name,lv_uuid,lv_size,lv_tags,lv_attr,segtype,lv_kernel_major,lv_kernel_minor"])?;
    let blocks = owned_command(inventory,Program::Lsblk, lsblk_inventory_args())?;
    let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map_err(|_| "cannot read Linux boot identity")?;
    if !crate::storage_lifecycle::valid_uuid(boot.trim()) {
        return Err("invalid Linux boot identity".into());
    }
    let mut result = validate_inventory_owned(inventory,cfg, &pvs, &vgs, &lvs, &blocks, boot.trim().into())?;
    result.drbd_module_version = match std::fs::read_to_string("/sys/module/drbd/version") {
        Ok(s) => Some(s.trim().into()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(_) => return Err("cannot inspect DRBD module version".into()),
    };
    Ok(result)
}

pub(in crate::storage_driver) fn prepared_context_owned(inventory:&InheritedOwnedPoolInventory,cfg:&Config,uid:&Uid)->Result<(Dir,std::fs::File,Pool,LocalRecord,Lv),String>{
    let dir=Dir::open(&cfg.journal_path(),false)?;
    let lock=dir.lock_existing()?;
    let bytes=dir.read("pool.json")?.ok_or("existing pool binding is required for read-only observation")?;
    let binding:Binding=serde_json::from_slice(&bytes).map_err(|_|"corrupt pool identity journal")?;
    if binding!=Binding::from(cfg){return Err("pool observation binding changed".into());}
    let pool=inspect_owned(inventory,cfg)?;
    let record=load(&dir,uid)?.ok_or("prepared allocation journal required")?;
    validate_record(cfg,&record)?;
    if record.stage!=Stage::Prepared{return Err("read-only replica observation requires Prepared allocation".into());}
    let lv=owned_lv(&pool,cfg,&record)?.ok_or("exact prepared LV disappeared")?.clone();
    Ok((dir,lock,pool,record,lv))
}

