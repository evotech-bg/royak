//! Literal readonly util-linux observations and pure inventory-guard regressions.
//! These are DATA/model checks, not actual whole-LVM admission, device writes,
//! root-disk erasure tests, mounted-path exceptions, grants or physical proof.
use super::*;
use serde_json::json;
use std::collections::BTreeMap;

struct ObservedRaw {
    node: u8,
    version: &'static str,
    version_sha256: &'static str,
    flat: &'static str,
    flat_sha256: &'static str,
    tree: &'static str,
    tree_sha256: &'static str,
}
const OBSERVED: [ObservedRaw; 3] = [
    ObservedRaw {
        node: 1,
        version: r####"lsblk from util-linux 2.39.3
"####,
        version_sha256: "f9a974080dc7763c649d9438cf16ee1163713e83545e2da3b8e56b66047b39e6",
        flat: r####"{
   "blockdevices": [
      {
         "path": "/dev/sda",
         "type": "disk",
         "serial": "2W2S7ABN4DWMV2M99KXY",
         "mountpoints": [
             null
         ]
      },{
         "path": "/dev/sda1",
         "type": "part",
         "serial": null,
         "mountpoints": [
             "/"
         ]
      },{
         "path": "/dev/sda15",
         "type": "part",
         "serial": null,
         "mountpoints": [
             "/boot/efi"
         ]
      },{
         "path": "/dev/sdb",
         "type": "disk",
         "serial": "BDHFXR68NYMM575M31KH",
         "mountpoints": [
             null
         ]
      },{
         "path": "/dev/sdc",
         "type": "disk",
         "serial": "DFAMECJANAJMQ8HA7BZW",
         "mountpoints": [
             null
         ]
      },{
         "path": "/dev/sr0",
         "type": "rom",
         "serial": "-_31415B265",
         "mountpoints": [
             null
         ]
      },{
         "path": "/dev/mapper/rkqs60fd6a50-data",
         "type": "lvm",
         "serial": null,
         "mountpoints": [
             null
         ]
      },{
         "path": "/dev/mapper/rkqs60fd6a50-rkvol_3f4df5b6c1d00882baec9ad4fbb8e920",
         "type": "lvm",
         "serial": null,
         "mountpoints": [
             null
         ]
      },{
         "path": "/dev/mapper/rkqs60fd6a50-rkvol_4aaafe801d8b88b38b35c674696172d3",
         "type": "lvm",
         "serial": null,
         "mountpoints": [
             null
         ]
      },{
         "path": "/dev/sda16",
         "type": "part",
         "serial": null,
         "mountpoints": [
             "/boot"
         ]
      }
   ]
}
"####,
        flat_sha256: "2fb54851a7f99b3fd1b33d04530505cbb973be2150b4813ee4c0483bf9e6b401",
        tree: r####"{
   "blockdevices": [
      {
         "path": "/dev/sda",
         "type": "disk",
         "serial": "2W2S7ABN4DWMV2M99KXY",
         "mountpoints": [
             null
         ],
         "children": [
            {
               "path": "/dev/sda1",
               "type": "part",
               "serial": null,
               "mountpoints": [
                   "/"
               ]
            },{
               "path": "/dev/sda15",
               "type": "part",
               "serial": null,
               "mountpoints": [
                   "/boot/efi"
               ]
            },{
               "path": "/dev/sda16",
               "type": "part",
               "serial": null,
               "mountpoints": [
                   "/boot"
               ]
            }
         ]
      },{
         "path": "/dev/sdb",
         "type": "disk",
         "serial": "BDHFXR68NYMM575M31KH",
         "mountpoints": [
             null
         ],
         "children": [
            {
               "path": "/dev/mapper/rkqs60fd6a50-data",
               "type": "lvm",
               "serial": null,
               "mountpoints": [
                   null
               ]
            },{
               "path": "/dev/mapper/rkqs60fd6a50-rkvol_3f4df5b6c1d00882baec9ad4fbb8e920",
               "type": "lvm",
               "serial": null,
               "mountpoints": [
                   null
               ]
            },{
               "path": "/dev/mapper/rkqs60fd6a50-rkvol_4aaafe801d8b88b38b35c674696172d3",
               "type": "lvm",
               "serial": null,
               "mountpoints": [
                   null
               ]
            }
         ]
      },{
         "path": "/dev/sdc",
         "type": "disk",
         "serial": "DFAMECJANAJMQ8HA7BZW",
         "mountpoints": [
             null
         ]
      },{
         "path": "/dev/sr0",
         "type": "rom",
         "serial": "-_31415B265",
         "mountpoints": [
             null
         ]
      }
   ]
}
"####,
        tree_sha256: "08c14f4215d4b4ef298081717e242c59c43d26735f073da25ae9d544931f489f",
    },
    ObservedRaw {
        node: 2,
        version: r####"lsblk from util-linux 2.39.3
"####,
        version_sha256: "f9a974080dc7763c649d9438cf16ee1163713e83545e2da3b8e56b66047b39e6",
        flat: r####"{
   "blockdevices": [
      {
         "path": "/dev/sda",
         "type": "disk",
         "serial": "8TJ4QMNBWRH499QGS0C8",
         "mountpoints": [
             null
         ]
      },{
         "path": "/dev/sda1",
         "type": "part",
         "serial": null,
         "mountpoints": [
             "/"
         ]
      },{
         "path": "/dev/sda15",
         "type": "part",
         "serial": null,
         "mountpoints": [
             "/boot/efi"
         ]
      },{
         "path": "/dev/sdb",
         "type": "disk",
         "serial": "APD3QNB0TEF4NDFHC057",
         "mountpoints": [
             null
         ]
      },{
         "path": "/dev/sdc",
         "type": "disk",
         "serial": "PATYXD85KCJMD91GF32M",
         "mountpoints": [
             null
         ]
      },{
         "path": "/dev/sr0",
         "type": "rom",
         "serial": "-_31415B265",
         "mountpoints": [
             null
         ]
      },{
         "path": "/dev/mapper/rkqs60fd6a50-data",
         "type": "lvm",
         "serial": null,
         "mountpoints": [
             null
         ]
      },{
         "path": "/dev/mapper/rkqs60fd6a50-rkvol_3f4df5b6c1d00882baec9ad4fbb8e920",
         "type": "lvm",
         "serial": null,
         "mountpoints": [
             null
         ]
      },{
         "path": "/dev/mapper/rkqs60fd6a50-rkvol_4aaafe801d8b88b38b35c674696172d3",
         "type": "lvm",
         "serial": null,
         "mountpoints": [
             null
         ]
      },{
         "path": "/dev/sda16",
         "type": "part",
         "serial": null,
         "mountpoints": [
             "/boot"
         ]
      }
   ]
}
"####,
        flat_sha256: "7024be7c29f3db7130e78f1d119857eb40149e52eefa8bfebd0b9ca08bdfa630",
        tree: r####"{
   "blockdevices": [
      {
         "path": "/dev/sda",
         "type": "disk",
         "serial": "8TJ4QMNBWRH499QGS0C8",
         "mountpoints": [
             null
         ],
         "children": [
            {
               "path": "/dev/sda1",
               "type": "part",
               "serial": null,
               "mountpoints": [
                   "/"
               ]
            },{
               "path": "/dev/sda15",
               "type": "part",
               "serial": null,
               "mountpoints": [
                   "/boot/efi"
               ]
            },{
               "path": "/dev/sda16",
               "type": "part",
               "serial": null,
               "mountpoints": [
                   "/boot"
               ]
            }
         ]
      },{
         "path": "/dev/sdb",
         "type": "disk",
         "serial": "APD3QNB0TEF4NDFHC057",
         "mountpoints": [
             null
         ],
         "children": [
            {
               "path": "/dev/mapper/rkqs60fd6a50-data",
               "type": "lvm",
               "serial": null,
               "mountpoints": [
                   null
               ]
            },{
               "path": "/dev/mapper/rkqs60fd6a50-rkvol_3f4df5b6c1d00882baec9ad4fbb8e920",
               "type": "lvm",
               "serial": null,
               "mountpoints": [
                   null
               ]
            },{
               "path": "/dev/mapper/rkqs60fd6a50-rkvol_4aaafe801d8b88b38b35c674696172d3",
               "type": "lvm",
               "serial": null,
               "mountpoints": [
                   null
               ]
            }
         ]
      },{
         "path": "/dev/sdc",
         "type": "disk",
         "serial": "PATYXD85KCJMD91GF32M",
         "mountpoints": [
             null
         ]
      },{
         "path": "/dev/sr0",
         "type": "rom",
         "serial": "-_31415B265",
         "mountpoints": [
             null
         ]
      }
   ]
}
"####,
        tree_sha256: "dccf1cfe72336e1ecfa4f70721733b21afa4e408dc8d16bb906f5ab83046639c",
    },
    ObservedRaw {
        node: 3,
        version: r####"lsblk from util-linux 2.39.3
"####,
        version_sha256: "f9a974080dc7763c649d9438cf16ee1163713e83545e2da3b8e56b66047b39e6",
        flat: r####"{
   "blockdevices": [
      {
         "path": "/dev/sda",
         "type": "disk",
         "serial": "DNHNXR4BZ424D9FRYHG7",
         "mountpoints": [
             null
         ]
      },{
         "path": "/dev/sda1",
         "type": "part",
         "serial": null,
         "mountpoints": [
             "/"
         ]
      },{
         "path": "/dev/sda15",
         "type": "part",
         "serial": null,
         "mountpoints": [
             "/boot/efi"
         ]
      },{
         "path": "/dev/sdb",
         "type": "disk",
         "serial": "B04H97FMDWJMQ1PE4YDD",
         "mountpoints": [
             null
         ]
      },{
         "path": "/dev/sdc",
         "type": "disk",
         "serial": "W4XVXWS3ZHT4B3WKB41B",
         "mountpoints": [
             null
         ]
      },{
         "path": "/dev/sr0",
         "type": "rom",
         "serial": "-_31415B265",
         "mountpoints": [
             null
         ]
      },{
         "path": "/dev/mapper/rkqs60fd6a50-data",
         "type": "lvm",
         "serial": null,
         "mountpoints": [
             null
         ]
      },{
         "path": "/dev/mapper/rkqs60fd6a50-rkvol_3f4df5b6c1d00882baec9ad4fbb8e920",
         "type": "lvm",
         "serial": null,
         "mountpoints": [
             null
         ]
      },{
         "path": "/dev/mapper/rkqs60fd6a50-rkvol_4aaafe801d8b88b38b35c674696172d3",
         "type": "lvm",
         "serial": null,
         "mountpoints": [
             null
         ]
      },{
         "path": "/dev/sda16",
         "type": "part",
         "serial": null,
         "mountpoints": [
             "/boot"
         ]
      }
   ]
}
"####,
        flat_sha256: "18f377ccff7c7ee0611109832e915e07de6f060a3ed1d37559dea6fc03c482c4",
        tree: r####"{
   "blockdevices": [
      {
         "path": "/dev/sda",
         "type": "disk",
         "serial": "DNHNXR4BZ424D9FRYHG7",
         "mountpoints": [
             null
         ],
         "children": [
            {
               "path": "/dev/sda1",
               "type": "part",
               "serial": null,
               "mountpoints": [
                   "/"
               ]
            },{
               "path": "/dev/sda15",
               "type": "part",
               "serial": null,
               "mountpoints": [
                   "/boot/efi"
               ]
            },{
               "path": "/dev/sda16",
               "type": "part",
               "serial": null,
               "mountpoints": [
                   "/boot"
               ]
            }
         ]
      },{
         "path": "/dev/sdb",
         "type": "disk",
         "serial": "B04H97FMDWJMQ1PE4YDD",
         "mountpoints": [
             null
         ],
         "children": [
            {
               "path": "/dev/mapper/rkqs60fd6a50-data",
               "type": "lvm",
               "serial": null,
               "mountpoints": [
                   null
               ]
            },{
               "path": "/dev/mapper/rkqs60fd6a50-rkvol_3f4df5b6c1d00882baec9ad4fbb8e920",
               "type": "lvm",
               "serial": null,
               "mountpoints": [
                   null
               ]
            },{
               "path": "/dev/mapper/rkqs60fd6a50-rkvol_4aaafe801d8b88b38b35c674696172d3",
               "type": "lvm",
               "serial": null,
               "mountpoints": [
                   null
               ]
            }
         ]
      },{
         "path": "/dev/sdc",
         "type": "disk",
         "serial": "W4XVXWS3ZHT4B3WKB41B",
         "mountpoints": [
             null
         ]
      },{
         "path": "/dev/sr0",
         "type": "rom",
         "serial": "-_31415B265",
         "mountpoints": [
             null
         ]
      }
   ]
}
"####,
        tree_sha256: "0563b18280641f546485779fc607d14a94c478bd5bb23431c12e974a20fba600",
    },
];

fn data_inventory(c: &Config) -> (Value, Value, Value) {
    (
        json!({"report":[{"pv":[{"pv_name":"/dev/sdb","pv_uuid":c.pv_uuid,"vg_name":c.vg_name,"vg_uuid":c.vg_uuid}]}]}),
        json!({"report":[{"vg":[{"vg_name":c.vg_name,"vg_uuid":c.vg_uuid,"vg_size":"2143289344.00","vg_free":"1073741824.00","vg_extent_size":"4194304.00"}]}]}),
        json!({"report":[{"lv":[]}]}),
    )
}
fn selected_data_tree(c: &Config, children: Value) -> Value {
    json!({"blockdevices":[{"path":"/dev/sdb","type":"disk","serial":c.disk_serial,
        "mountpoints":[null],"children":children}]})
}
fn reject_data_tree(c: &Config, blocks: &Value) {
    let (p,v,l)=data_inventory(c);
    assert!(validate_inventory(c,&p,&v,&l,blocks,"DATA-only-model-boot".into()).is_err());
}
fn device_map(value: &Value) -> BTreeMap<String,Value> {
    let mut rows=Vec::new();
    flatten(value["blockdevices"].as_array().unwrap(),&mut rows).unwrap();
    let mut result=BTreeMap::new();
    for row in rows {
        let mut device=row.clone();
        device.as_object_mut().unwrap().remove("children");
        assert!(result.insert(row["path"].as_str().unwrap().to_string(),device).is_none());
    }
    result
}
#[test]
fn actual_inventory_callee_requests_explicit_tree_with_exact_columns() {
    assert_eq!(lsblk_inventory_args(),
        ["--json","--bytes","-o","PATH,TYPE,SERIAL,MOUNTPOINTS","--tree"].as_slice());
}
#[test]
fn all_three_literal_readonly_raw_versions_and_inventory_hashes_are_exact() {
    for fixture in &OBSERVED {
        assert!((1..=3).contains(&fixture.node));
        assert_eq!(fixture.version,"lsblk from util-linux 2.39.3\n");
        for (raw,pin) in [(fixture.version,fixture.version_sha256),
            (fixture.flat,fixture.flat_sha256),(fixture.tree,fixture.tree_sha256)] {
            assert!(raw.ends_with('\n'));
            assert_eq!(format!("{:x}",Sha256::digest(raw.as_bytes())),pin);
        }
    }
}
#[test]
fn real_flat_and_tree_preserve_devices_but_only_tree_links_mounted_descendants() {
    for fixture in &OBSERVED {
        let flat:Value=serde_json::from_str(fixture.flat).unwrap();
        let tree:Value=serde_json::from_str(fixture.tree).unwrap();
        assert_eq!(flat["blockdevices"].as_array().unwrap().len(),10);
        assert_eq!(tree["blockdevices"].as_array().unwrap().len(),4);
        assert_eq!(device_map(&flat),device_map(&tree));
        assert!(flat["blockdevices"].as_array().unwrap().iter().all(|row|row.get("children").is_none()));
        let parent=tree["blockdevices"].as_array().unwrap().iter().find(|row|row["path"]=="/dev/sda").unwrap();
        let mut mounts=parent["children"].as_array().unwrap().iter().flat_map(|row|
            row["mountpoints"].as_array().unwrap().iter().filter_map(Value::as_str)).collect::<Vec<_>>();
        mounts.sort_unstable();
        assert_eq!(mounts,vec!["/","/boot","/boot/efi"]);
    }
}
#[test]
fn real_selected_parent_tree_refuses_descendants_where_flat_parent_is_blind() {
    for fixture in &OBSERVED {
        let flat:Value=serde_json::from_str(fixture.flat).unwrap();
        let tree:Value=serde_json::from_str(fixture.tree).unwrap();
        let flat_parent=flat["blockdevices"].as_array().unwrap().iter().find(|row|row["path"]=="/dev/sda").unwrap();
        let tree_parent=tree["blockdevices"].as_array().unwrap().iter().find(|row|row["path"]=="/dev/sda").unwrap();
        assert_eq!(flat_parent["mountpoints"],json!([null]));
        // A pure subtree guard on disconnected flat DATA is blind. This is NOT
        // evidence that complete real LVM admission or a destructive command ran.
        assert!(unmounted_tree(flat_parent).is_ok());
        assert!(unmounted_tree(tree_parent).unwrap_err().contains("mounted filesystem or swap"));
    }
}
#[test]
fn selected_parent_swap_descendant_is_refused_without_path_or_type_exception() {
    let c=super::super::test_config();
    let blocks=selected_data_tree(&c,json!([{"path":"/dev/foreign-data","type":"lvm",
        "serial":"not-the-approved-serial","mountpoints":["[SWAP]"]}]));
    reject_data_tree(&c,&blocks);
}
#[test]
fn malformed_selected_children_never_mean_unmounted_or_empty() {
    let c=super::super::test_config();
    for children in [Value::Null,json!({}),json!("unknown"),json!([7])] {
        reject_data_tree(&c,&selected_data_tree(&c,children));
    }
}
#[test]
fn selected_mounted_sibling_is_not_hidden_by_unmounted_or_foreign_serials() {
    let c=super::super::test_config();
    let blocks=selected_data_tree(&c,json!([
        {"path":"/dev/data-a","mountpoints":[null]},
        {"path":"/dev/data-b","serial":"foreign-child","mountpoints":["/foreign-sibling-mount"]}
    ]));
    reject_data_tree(&c,&blocks);
}
#[test]
fn unrelated_mounted_branch_does_not_globally_deny_unmounted_selected_pool() {
    let c=super::super::test_config();let (p,v,l)=data_inventory(&c);
    let mut blocks=selected_data_tree(&c,json!([]));
    blocks["blockdevices"].as_array_mut().unwrap().push(json!({
        "path":"/dev/unrelated-disk","type":"disk","serial":"unrelated-mounted-branch",
        "mountpoints":[null],"children":[{"path":"/dev/unrelated-part","mountpoints":["/"]}]
    }));
    let pool=validate_inventory(&c,&p,&v,&l,&blocks,"DATA-only-model-boot".into()).unwrap();
    assert_eq!(pool.disk_path,"/dev/sdb");
    assert!(!pool.pod_access_granted);
}
#[test]
fn deep_selected_descendant_keeps_existing_recursive_mount_refusal() {
    let c=super::super::test_config();
    let mut descendant=json!({"mountpoints":["/deep-mounted-DATA"]});
    for _ in 0..32 {descendant=json!({"mountpoints":[null],"children":[descendant]});}
    reject_data_tree(&c,&selected_data_tree(&c,json!([descendant])));
}
#[test]
fn missing_or_malformed_mount_inventory_is_not_an_empty_selected_subtree() {
    let c=super::super::test_config();
    for mounts in [Value::Null,json!("unknown"),json!(false)] {
        reject_data_tree(&c,&selected_data_tree(&c,json!([{"mountpoints":mounts}])));
    }
    reject_data_tree(&c,&selected_data_tree(&c,json!([{"path":"/dev/missing-mounts"}])));
    let mut blocks=selected_data_tree(&c,json!([]));
    blocks["blockdevices"][0].as_object_mut().unwrap().remove("mountpoints");
    reject_data_tree(&c,&blocks);
}
