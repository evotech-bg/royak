// Include inside src/servicelb.rs's existing tests module after applying 03.
#[test]
fn conflict_cache_retains_only_current_snapshot_not_churn_history(){
    let mut current=std::collections::HashSet::new();
    for n in 0..10_000 {
        let msg=format!("port 30000: ns/service-{n} conflicts with ns/other-{n}");
        let next=std::collections::HashSet::from([msg.clone()]);
        assert_eq!(refresh_conflict_cache(&mut current,next.clone()),vec![msg]);
        assert_eq!(current.len(),1);
        assert!(refresh_conflict_cache(&mut current,next).is_empty());
    }
    assert!(refresh_conflict_cache(&mut current,std::collections::HashSet::new()).is_empty());
    assert!(current.is_empty());
    let msg="conflict-returned".to_string();
    assert_eq!(refresh_conflict_cache(&mut current,std::collections::HashSet::from([msg.clone()])),vec![msg]);
}
