////웹서버 생성
const express = require('express');
const vhost = require('vhost');
const server = express();
const gameServer = express();
const gameServer1 = express();
const gameServer2 = express();
var bongPort = 3000;
var gamePort = 80;
server.use(express.static(__dirname+"/cssfile"));

////DB 연동
var i = 0;
var mysql = require('mysql')
var connection = mysql.createConnection({
    host : 'localhost',
    user : 'root',
    password : '1234',
    database : 'testdb'
});

connection.connect();

server.set('view engine', 'ejs');

//로그인 페이지
server.get('/', (req, res) =>{
    res.sendFile(__dirname+"/index.html")
});

///DB 방문기록 쿼리
server.get("/bongnet", (req, res)=>{
    connection.query("select * from testip limit 10", function(error, results){
        res.render("list.ejs",{post: results});
    });
});
 
//블록리스트
server.use(express.urlencoded({extened : true}));

server.set('view engine', 'ejs');

server.get("/blockList", (req, res) => {
    res.render('yong.ejs', {title:output});
})

let output = [];
server.post('/app.js' , (req,res) =>{
    if(req.body.select){
        connection.query(`select * from warningTest where host_name = '${req.body.select}'`, (err,res)=>{
            if(res[0]===undefined){}
            else    output.push(res[0].host_name);
        })
    }
    else if(req.body.add){
        connection.query(`select * from warningTest where host_name = '${req.body.add}'`, (err,res)=>{
            if(res[0]===undefined){
                connection.query(`insert into warningTest value('${req.body.add}')`, (err,res)=>{
                    if(err) throw err;               
                })
            }
        })
    }
    else if(req.body.drop){
        connection.query(`delete from warningTest where host_name = '${req.body.drop}'`, (err)=>{
            if(err) throw err;
        });
    }
    else if(!req.body.select){
        connection.query(`select host_name from warningTest`, (err,res)=>{
            if(err) throw err;
            for(let i = 0 ; i < res.length ; i ++){
                output.push(res[i].host_name);
                //console.log(`output[${i}] : ${output[i]}`);
            }
        })
    }
  
    output = [];
    res.redirect('/blockList');
    
})

gameServer1.get('/', (req, res) => {
    setTimeout(function() {
        res.sendFile(__dirname + "/maple.html")
      }, 3000);
});

gameServer2.get('/', (req, res) => {
    setTimeout(function() {
        res.sendFile(__dirname + "/lostark.html")
      }, 3000);
});

gameServer.use(vhost("maple.bong", gameServer1));
gameServer.use(vhost("lostark.bong", gameServer2));

server.use((req,res)=>{
    res.sendFile(__dirname+"/noPage.html")
})

server.listen(bongPort,() => {
    console.log(`Example app listening on port ${bongPort}`)
})

gameServer.listen(gamePort,() => {
    console.log(`Example app listening on port ${gamePort}`)
})