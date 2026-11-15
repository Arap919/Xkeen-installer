package smb2

import (
 "context"
 "errors"
 "fmt"
 "net"
 "os"
 "testing"
 "time"

 wire "github.com/cloudsoda/go-smb2/internal/smb2"
 "github.com/cloudsoda/go-smb2/internal/erref"
)

// This wire fixture starts at an established guest session and exercises real
// CREATE, SET_INFO(FileRenameInformation) and CLOSE encoding/response handling.
// It does not test negotiation, authentication, or an operating-system SMB server.
func TestRenameNoReplaceWirePreservesCollision(t *testing.T) {
 for _,tc:=range []struct{name string;exists,legacy bool;flag byte;want string;collision bool}{
  {"absent",false,false,0,"new",false},
  {"collision",true,false,0,"foreign",true},
  {"legacy-overwrite",true,true,1,"new",false},
 }{
  t.Run(tc.name,func(t *testing.T){
   client,server:=net.Pipe()
   deadline:=time.Now().Add(2*time.Second);client.SetDeadline(deadline);server.SetDeadline(deadline)
   defer client.Close();defer server.Close()
   c:=&conn{
    t:direct(client),outstandingRequests:newOutstandingRequests(),account:openAccount(128),
    rdone:make(chan struct{},1),wdone:make(chan struct{},1),write:make(chan []byte,1),werr:make(chan error,1),
    dialect:wire.SMB302,maxReadSize:1<<20,maxWriteSize:1<<20,maxTransactSize:1<<20,
    capabilities:wire.SMB2_GLOBAL_CAP_LARGE_MTU,
   }
   go c.runSender();go c.runReceiver()
   defer func(){select{case c.rdone<-struct{}{}:default:}}()
   session:=&session{conn:c,sessionFlags:wire.SMB2_SESSION_FLAG_IS_GUEST}
   c.session.Store(session)
   ctx,cancel:=context.WithDeadline(context.Background(),deadline);defer cancel()
   share:=&Share{treeConn:&treeConn{session:session},ctx:ctx}
   result:=make(chan error,1)
   go func(){
    tr:=direct(server);target:="";if tc.exists{target="foreign"}
    for _,command:=range []uint16{wire.SMB2_CREATE,wire.SMB2_SET_INFO,wire.SMB2_CLOSE}{
     n,e:=tr.ReadSize();if e!=nil{result<-e;return}
     if n<64||n>65536{result<-fmt.Errorf("bad fixture frame %d",n);return}
     request:=make([]byte,n);if _,e=tr.Read(request);e!=nil{result<-e;return}
     p:=wire.PacketCodec(request);if p.Command()!=command{result<-fmt.Errorf("unexpected command %d",p.Command());return}
     header:=wire.PacketHeader{Flags:wire.SMB2_FLAGS_SERVER_TO_REDIR,Command:command,MessageId:p.MessageId(),SessionId:p.SessionId(),TreeId:p.TreeId(),CreditRequestResponse:p.CreditRequest()}
     var response wire.Packet
     switch command{
     case wire.SMB2_CREATE:
      zeroTime:=&wire.Filetime{}
      response=&wire.CreateResponse{PacketHeader:header,FileId:&wire.FileId{},CreationTime:zeroTime,LastAccessTime:zeroTime,LastWriteTime:zeroTime,ChangeTime:zeroTime}
     case wire.SMB2_SET_INFO:
      r:=wire.SetInfoRequestDecoder(request[64:])
      if r.IsInvalid()||r.FileInfoClass()!=wire.FileRenameInformation{result<-errors.New("unexpected SET_INFO class");return}
      offset:=int(r.BufferOffset())
      if offset>=len(request)||request[offset]!=tc.flag{result<-errors.New("wrong ReplaceIfExists byte on wire");return}
      if target!=""&&request[offset]==0{
       header.Status=uint32(erref.STATUS_OBJECT_NAME_COLLISION)
       response=&wire.ErrorResponse{PacketHeader:header}
      }else{target="new";response=&wire.SetInfoResponse{PacketHeader:header}}
     case wire.SMB2_CLOSE:
      zeroTime:=&wire.Filetime{}
      response=&wire.CloseResponse{PacketHeader:header,CreationTime:zeroTime,LastAccessTime:zeroTime,LastWriteTime:zeroTime,ChangeTime:zeroTime}
     }
     buf:=make([]byte,response.Size());response.Encode(buf)
     if _,e=tr.Write(buf);e!=nil{result<-e;return}
    }
    if target!=tc.want{result<-fmt.Errorf("target overwritten: got %q want %q",target,tc.want);return}
    result<-nil
   }()
   var err error
   if tc.legacy{err=share.Rename("install/temp","install/archive.tgz")}else{err=share.RenameNoReplace("install/temp","install/archive.tgz")}
   if tc.collision{
    // accept normalizes STATUS_OBJECT_NAME_COLLISION to os.ErrExist.
    if !errors.Is(err,os.ErrExist){t.Fatalf("collision was not preserved: %v",err)}
   }else if err!=nil{t.Fatal(err)}
   select{case err:=<-result:if err!=nil{t.Fatal(err)};case <-ctx.Done():t.Fatal("wire fixture stalled")}
  })
 }
}

