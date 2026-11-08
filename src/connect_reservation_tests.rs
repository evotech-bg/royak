// Include inside src/connect.rs's existing tests module after applying 02.
#[tokio::test]
async fn active_reservation_survives_dropped_handler_until_blocking_job_exits(){
    let session=session_for_test(700,700);
    let lease=ActiveLease::acquire(&session).unwrap();
    let (entered_tx,entered_rx)=tokio::sync::oneshot::channel();
    let (release_tx,release_rx)=std::sync::mpsc::channel();
    let handler=tokio::spawn(async move {
        active_blocking(&lease,move||{let _=entered_tx.send(());release_rx.recv().unwrap();}).await;
    });
    entered_rx.await.unwrap();
    handler.abort();let _=handler.await;
    assert_eq!(session.active.load(Ordering::SeqCst),1,"detached real worker still owns capacity");
    release_tx.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(2),async{
        while session.active.load(Ordering::SeqCst)!=0 {tokio::task::yield_now().await;}
    }).await.unwrap();
}
#[tokio::test]
async fn active_reservation_drops_once_when_upgrade_owner_is_cancelled(){
    let session=session_for_test(701,701);
    let owner=ActiveLease::acquire(&session).unwrap();
    let task_owner=owner.hold();drop(owner);
    assert_eq!(session.active.load(Ordering::SeqCst),1);
    let (ready_tx,ready_rx)=tokio::sync::oneshot::channel();
    let task=tokio::spawn(async move{let _owner=task_owner;let _=ready_tx.send(());std::future::pending::<()>().await;});
    ready_rx.await.unwrap();task.abort();let _=task.await;
    assert_eq!(session.active.load(Ordering::SeqCst),0);
}
#[test]
fn active_reservation_limit_and_clones_do_not_double_count_or_double_release(){
    let session=session_for_test(702,702);
    let held:Vec<_>=(0..8).map(|_|ActiveLease::acquire(&session).unwrap()).collect();
    assert!(ActiveLease::acquire(&session).is_none());
    let worker=held[0].hold();drop(held);
    assert_eq!(session.active.load(Ordering::SeqCst),1);
    drop(worker);assert_eq!(session.active.load(Ordering::SeqCst),0);
}
