'use strict';
/* ผีกบกระโดดถีบ — เซิร์ฟเวอร์ (Node 18+, ไม่มี dependency)
   - ส่งไฟล์เกมจาก public/ (หรือโฟลเดอร์เดียวกัน)
   - ห้องออนไลน์ผ่าน WebSocket ที่ /ws?room=fg-xxxxx
   - สิทธิ์ Admin ตรวจที่เซิร์ฟเวอร์ (ตัวแปร ADMIN_CODE) + เจ้าของห้อง (owner) ตัดสินที่เซิร์ฟเวอร์
   - คำสั่ง Admin ผ่านเซิร์ฟเวอร์เสมอ: ตรวจสิทธิ์ → บันทึก log → ส่งต่อให้เจ้าของห้อง  */
const http=require('http'),fs=require('fs'),path=require('path'),crypto=require('crypto');
const PORT=parseInt(process.env.PORT,10)||3000;
const PUB=fs.existsSync(path.join(__dirname,'public','index.html'))?path.join(__dirname,'public'):__dirname;
let ADMIN_CODE=process.env.ADMIN_CODE;
if(!ADMIN_CODE){ADMIN_CODE='FROG-7391';console.warn('[เตือน] ยังไม่ได้ตั้ง ADMIN_CODE ใช้ค่าเริ่มต้น "'+ADMIN_CODE+'" — ควรตั้งค่าใหม่ใน Environment ของโฮสต์');}
const MAX_PEERS=6,MAX_MSG=32*1024,MAX_PRESENCE=48*1024,RATE=80;
const MIME={'.html':'text/html; charset=utf-8','.js':'application/javascript; charset=utf-8','.css':'text/css; charset=utf-8','.png':'image/png','.ico':'image/x-icon','.mp3':'audio/mpeg','.json':'application/json'};
const PRIVATE=/^\/(server\.js|package\.json|render\.yaml|README\.md|\.gitignore)$/;

const rooms=new Map();      // name -> {peers:Map, owner:id, log:[]}
const fails=new Map();      // ip -> {n,until,t}
let nextId=1;

function ipOf(req){return String(req.headers['x-forwarded-for']||req.socket.remoteAddress||'').split(',')[0].trim();}
function checkCode(code){
  const a=crypto.createHash('sha256').update(String(code||'').trim().toUpperCase()).digest();
  const b=crypto.createHash('sha256').update(ADMIN_CODE.toUpperCase()).digest();
  return crypto.timingSafeEqual(a,b);
}
function tryAuth(ip,code){
  const now=Date.now();let f=fails.get(ip);if(!f){f={n:0,until:0,t:now};fails.set(ip,f);}
  if(f.until>now)return {ok:false,wait:Math.ceil((f.until-now)/1000)};
  if(now-f.t>60000){f.n=0;f.t=now;}
  if(checkCode(code)){f.n=0;return {ok:true};}
  if(++f.n>=5){f.until=now+5*60000;f.n=0;return {ok:false,wait:300};}
  return {ok:false};
}
const server=http.createServer((req,res)=>{
  let p;try{p=decodeURIComponent((req.url||'/').split('?')[0]);}catch(e){res.writeHead(400);res.end();return;}
  if(p==='/healthz'){res.writeHead(200,{'content-type':'text/plain'});res.end('ok');return;}
  if(p==='/api/admin-check'&&req.method==='POST'){
    let body='';req.on('data',c=>{body+=c;if(body.length>1000)req.destroy();});
    req.on('end',()=>{
      let code='';try{code=JSON.parse(body).code;}catch(e){}
      const r=tryAuth(ipOf(req),code);
      if(r.ok)console.log('[admin] solo auth ok',ipOf(req));
      res.writeHead(200,{'content-type':'application/json'});res.end(JSON.stringify(r));
    });
    return;
  }
  if(p==='/')p='/index.html';
  if(PRIVATE.test(p)){res.writeHead(404);res.end('not found');return;}
  const f=path.normalize(path.join(PUB,p));
  if(f.indexOf(PUB)!==0){res.writeHead(403);res.end();return;}
  fs.readFile(f,(e,buf)=>{
    if(e){res.writeHead(404,{'content-type':'text/plain'});res.end('not found');return;}
    res.writeHead(200,{'content-type':MIME[path.extname(f)]||'application/octet-stream','cache-control':'no-cache'});
    res.end(buf);
  });
});

/* ---------- WebSocket (RFC 6455) ---------- */
function frame(op,payload){
  const len=payload.length;let h;
  if(len<126)h=Buffer.from([0x80|op,len]);
  else if(len<65536){h=Buffer.alloc(4);h[0]=0x80|op;h[1]=126;h.writeUInt16BE(len,2);}
  else{h=Buffer.alloc(10);h[0]=0x80|op;h[1]=127;h.writeBigUInt64BE(BigInt(len),2);}
  return Buffer.concat([h,payload]);
}
function send(p,obj){if(p.closed)return;try{p.sock.write(frame(1,Buffer.from(typeof obj==='string'?obj:JSON.stringify(obj))));}catch(e){}}
function bcast(room,obj,except){const s=JSON.stringify(obj);room.peers.forEach(q=>{if(q!==except)send(q,s);});}
function slog(room,p,text){
  const line=new Date().toISOString().slice(11,19)+' ['+(p.nick||p.id)+(p.admin?'*':'')+'] '+text;
  room.log.push(line);if(room.log.length>80)room.log.shift();
  console.log('['+p.room+'] '+line);
}
function authorized(room,p){return !!p.admin||room.owner===p.id;}
function closePeer(p){
  if(p.closed)return;p.closed=true;try{p.sock.write(frame(8,Buffer.alloc(0)));}catch(e){}try{p.sock.destroy();}catch(e){}
  leave(p);
}
function leave(p){
  const room=rooms.get(p.room);if(!room||!room.peers.has(p.id))return;
  room.peers.delete(p.id);
  bcast(room,{t:'l',peer:p.id});
  if(!room.peers.size){rooms.delete(p.room);return;}
  if(room.owner===p.id){ // โอนเจ้าของห้องให้คนที่เข้าก่อนสุด
    let best=null;room.peers.forEach(q=>{if(!best||q.joined<best.joined)best=q;});
    room.owner=best.id;bcast(room,{t:'own',peer:best.id});
  }
}
function sizeOf(o){try{return JSON.stringify(o).length;}catch(e){return 1e9;}}

function onMessage(p,text){
  const now=Date.now();
  if(now-p.rt>1000){p.rt=now;p.rc=0;}
  if(++p.rc>RATE)return;
  let m;try{m=JSON.parse(text);}catch(e){return;}
  if(!m||typeof m.t!=='string')return;
  const room=rooms.get(p.room);if(!room)return;
  if(m.t==='p'&&m.patch&&typeof m.patch==='object'&&!Array.isArray(m.patch)){
    const patch={};
    Object.keys(m.patch).slice(0,40).forEach(k=>{if(/^[a-zA-Z0-9_]{1,12}$/.test(k))patch[k]=m.patch[k];});
    const next=Object.assign({},p.presence);
    Object.keys(patch).forEach(k=>{if(patch[k]===null)delete next[k];else next[k]=patch[k];});
    if(sizeOf(next)>MAX_PRESENCE)return;
    p.presence=next;if(typeof patch.n==='string')p.nick=patch.n.slice(0,16);
    bcast(room,{t:'u',peer:p.id,patch:patch},p);
  }else if(m.t==='auth'){
    const r=tryAuth(p.ip,m.code);
    if(r.ok){p.admin=true;slog(room,p,'ปลดล็อกแอดมิน');bcast(room,{t:'adm',peer:p.id,on:true});}
    send(p,{t:'auth',ok:!!r.ok,wait:r.wait||0});
  }else if(m.t==='cmd'){
    if(!authorized(room,p)){slog(room,p,'ถูกปฏิเสธคำสั่ง (ไม่มีสิทธิ์): '+String(m.c).slice(0,40));send(p,{t:'deny'});return;}
    const c=String(m.c||'').slice(0,24),a=m.a==null?null:String(JSON.stringify(m.a)).slice(0,300);
    slog(room,p,'cmd '+c+(a?' '+a:''));
    const owner=room.peers.get(room.owner);
    if(owner)send(owner,{t:'cmd',from:p.id,c:c,a:m.a});
  }else if(m.t==='bc'){ // ประกาศทั่วเซิร์ฟเวอร์ (เฉพาะแอดมินที่ปลดล็อก)
    if(!p.admin)return;
    const text2=String(m.text||'').slice(0,120);slog(room,p,'ประกาศทั้งเซิร์ฟเวอร์: '+text2);
    rooms.forEach(r=>bcast(r,{t:'bc',text:text2}));
  }else if(m.t==='logreq'){
    if(!authorized(room,p))return;send(p,{t:'log',lines:room.log.slice(-40)});
  }else if(m.t==='sig'){ // ส่งต่อสัญญาณ WebRTC (เสียงพูด)
    const q=room.peers.get(String(m.to));if(q&&sizeOf(m.d)<8000)send(q,{t:'sig',from:p.id,d:m.d});
  }
}

server.on('upgrade',(req,sock)=>{
  const u=new URL(req.url,'http://x');
  const name=u.searchParams.get('room')||'';
  const key=req.headers['sec-websocket-key'];
  if(u.pathname!=='/ws'||!key||!/^fg-[a-z0-9]{5}$/.test(name)){sock.write('HTTP/1.1 400 Bad Request\r\n\r\n');sock.destroy();return;}
  const accept=crypto.createHash('sha1').update(key+'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64');
  sock.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: '+accept+'\r\n\r\n');
  sock.setNoDelay(true);
  const p={sock:sock,room:name,ip:ipOf(req),id:'p'+(nextId++).toString(36)+crypto.randomBytes(2).toString('hex'),presence:{},nick:'',admin:false,joined:Date.now(),closed:false,alive:true,rt:0,rc:0,buf:Buffer.alloc(0),frag:null};
  let room=rooms.get(name);if(!room){room={peers:new Map(),owner:null,log:[]};rooms.set(name,room);}
  if(room.peers.size>=MAX_PEERS){send(p,{t:'full'});p.closed=true;sock.destroy();return;}
  const others=[];room.peers.forEach(q=>others.push({peer:q.id,presence:q.presence,adm:q.admin}));
  room.peers.set(p.id,p);if(!room.owner)room.owner=p.id;
  send(p,{t:'hello',me:p.id,owner:room.owner,peers:others.concat([{peer:p.id,presence:{},adm:false}])});
  bcast(room,{t:'join',peer:p.id,presence:{}},p);

  sock.on('data',chunk=>{
    p.buf=Buffer.concat([p.buf,chunk]);
    if(p.buf.length>MAX_MSG*2){closePeer(p);return;}
    for(;;){
      const b=p.buf;if(b.length<2)return;
      const fin=!!(b[0]&0x80),op=b[0]&0x0f,masked=!!(b[1]&0x80);let len=b[1]&0x7f,off=2;
      if(!masked){closePeer(p);return;}
      if(len===126){if(b.length<4)return;len=b.readUInt16BE(2);off=4;}
      else if(len===127){if(b.length<10)return;const big=b.readBigUInt64BE(2);if(big>BigInt(MAX_MSG)){closePeer(p);return;}len=Number(big);off=10;}
      if(len>MAX_MSG){closePeer(p);return;}
      if(b.length<off+4+len)return;
      const mask=b.slice(off,off+4),data=Buffer.from(b.slice(off+4,off+4+len));
      for(let i=0;i<data.length;i++)data[i]^=mask[i&3];
      p.buf=b.slice(off+4+len);
      if(op===8){closePeer(p);return;}
      if(op===9){try{sock.write(frame(10,data));}catch(e){}continue;}
      if(op===10){p.alive=true;continue;}
      if(op===1||op===0){
        if(op===1)p.frag=[];
        if(!p.frag)continue;
        p.frag.push(data);
        if(fin){const txt=Buffer.concat(p.frag).toString('utf8');p.frag=null;onMessage(p,txt);}
      }
    }
  });
  sock.on('close',()=>{p.closed=true;leave(p);});
  sock.on('error',()=>{p.closed=true;try{sock.destroy();}catch(e){}leave(p);});
});

setInterval(()=>{
  rooms.forEach(room=>room.peers.forEach(p=>{
    if(!p.alive){closePeer(p);return;}
    p.alive=false;try{p.sock.write(frame(9,Buffer.alloc(0)));}catch(e){}
  }));
  const now=Date.now();fails.forEach((f,k)=>{if(f.until<now&&now-f.t>600000)fails.delete(k);});
},25000).unref();

server.listen(PORT,'0.0.0.0',()=>console.log('ผีกบกระโดดถีบ listening on '+PORT+' (files: '+PUB+')'));
