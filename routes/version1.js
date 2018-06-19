require('dotenv/config');
const express = require('express');
const router = express.Router();
const pool = require('../db.js');
const squel = require('squel');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');



// [user] login
router.post('/api/login', function(req, res, next){
    if (!req.body.username || !req.body.password){
        res.status(401).json({
            error_message: "REQUIRED FIELDS : (username, password)",
            user_error_message: "필수 항목을 모두 입력하십시오."
        });
    }
    else if(req.body.username.length > 20 || req.body.username.length < 4 || req.body.password.length > 20 ||  req.body.password.length < 4){
        res.status(401).json({
            error_type: "Data Integrity Violation",
            error_message: "username과 password는 4~20자리이어야 합니다."
        });
    }
    else{
        pool.getConnection(function(error, connection){
            if(error){
                if(typeof connection !== 'undefined'){
                    connection.release();
                }
                next(error);
            }
            else{
                var queryString = squel.select({separator: "\n"})
                                    .from('user')
                                    .field('user_id')
                                    .field('password')
                                    .field('user_full_name')
                                    .where('username = ?', req.body.username)
                                    .toString();
                connection.query(queryString, function(error, results, fields){
                    connection.release();
                    if (error){
                        next(error);
                    } 
                    else{
                        if (!!results[0]){
                            var password_stored = results[0].password;
                            var passwordIsValid = bcrypt.compareSync(req.body.password, password_stored);
                            if (passwordIsValid){
                                jwt.sign({username: req.body.username, user_id: results[0].user_id, user_first_name: results[0].user_first_name}, process.env.USER_SECRET_KEY, {expiresIn: '7d'}, function(error, token){
                                    if (error){
                                        next(error);
                                    }
                                    else{
                                    res.status(200).json({
                                        auth: true,
                                        token: token
                                    });
                                    }
                                });
                            }
                            else{
                                res.status(401).json({
                                    status: "id / 비밀번호가 일치 하지 않습니다.",
                                    auth: false,
                                    token: null
                                });
                            }
                        }
                        else{
                            res.status(401).json({
                                status: "해당 아이디가 존재 하지 않습니다.",
                                auth: false,
                                token: null
                            });
                        }
                    }
                });
            }
        });
    }
});


// [user] registration
router.post('/api/register', function(req, res, next){
    /*
    {
        "username":
        "password":
        "user_full_name":
        "user_email":
        "user_phone":
        "user_address_line1": (optional)
        "user_address_line2": (optional)
        "user_city": (optional)
        "user_postal_code": (optional)
        "user_country": (optional)
    }
    */
    if (!req.body.username || !req.body.password || !req.body.user_full_name || !req.body.user_email || !req.body.user_phone){
        res.status(401).json({
            error_message: "REQUIRED FIELDS : (username, password, user_full_name, user_email, user_phone)",
            user_error_message: "필수 항목을 모두 입력하십시오."
        });
    } else if (req.body.username.length < 4 || req.body.username.length > 20 || req.body.password.length < 4 || req.body.password.length > 20 ||
                req.body.user_phone.length > 20 || req.body.user_email.length > 30){
        res.status(401).json({
            error_type: "Data Integrity Violation",
            error_message: "입력하신 파라미터 글자 숫자를 참고하세요: username(4~20), password(4~20), phone(~20), email(~30)"
        });
    }
    else {
        pool.getConnection(function(error, connection){
            if(error){
                if(typeof connection !== 'undefined'){
                    connection.release();
                }
                next(error);
            }
            else{
                var selectString = squel.select({separator:'\n'})
                                        .from('user')
                                        .field('username')
                                        .where('username = ?', req.body.username)
                                        .toString();
                connection.query(selectString, function(error, results, fields){
                    if(error){
                        connection.release();
                        next(error);
                    }
                    if(Array.isArray(results) && !!results.length){ // checking if the select query found duplicate username
                        if(!!results[0].username){
                            connection.release();
                            res.status(401).json({
                                error_message: "이미 사용중인 username입니다."
                            });
                        }
                    }
                    else {
                        var hashedPassword = bcrypt.hashSync(req.body.password, parseInt(process.env.SALT_ROUNDS));
                        var queryString = squel.insert({separator: "\n"})
                                                .into('user')
                                                .set('admin_id', process.env.MASTER_ADMIN_ID) // assinged ADMIN is determined by .env file
                                                .set('username', req.body.username)
                                                .set('password', hashedPassword)
                                                .set('user_full_name', req.body.user_full_name)
                                                .set('user_email', req.body.email)
                                                .set('user_phone', req.body.phone)
                                                .set('user_address_line1', req.body.user_address_line1)
                                                .set('user_address_line2', req.body.user_address_line2)
                                                .set('user_city', req.body.user_city)
                                                .set('user_postal_code', req.body.user_postal_code)
                                                .set('user_country', req.body.user_country)
                                                .toString();
                        connection.query(queryString, function(error, results, fields){
                            connection.release();
                            if (error){
                                next(error);    
                            }
                            else{
                                jwt.sign({ user_id: results.user_id, username: req.body.username, user_full_name: req.body.user_full_name}, process.env.USER_SECRET_KEY, {expiresIn: '7d'}, function(error, token){
                                    if (error){
                                        next(error);
                                    }
                                    else{
                                        res.status(200).json({
                                            auth: true,
                                            token: token,
                                            results: results
                                        });
                                    }
                                });
                            }   
                        });
                    }
                    
                });
                
            }
        });
    }   
});


// [user] change password
router.put('/api/change_password', verifyToken, function(req, res, next){
    /*
    {
        "password": (current password)
        "new_password":
        "new_password_confirm":
    }
    */
    if(!req.body.password){
        res.status(401).json({
            error_message: "REQUIRED FIELD omitted",
            user_error_message: "비밀번호를 입력해주십시오."
        });
    }

    if(!req.body.new_password || !req.body.new_password_confirm){
        res.status(401).json({
            error_message: "REQUIRED FIELDS: (new_password, new_password_confirm) ",
            user_error_message: "새로운 비밀번호와 비밀번호 확인을 입력해주십시오."
        });
    }
    if(req.body.new_password.length < 4 || req.body.new_password.length > 20){
        res.status(401).json({
            error_type: "Date Integrity Violation",
            error_message: "비밀번호는 4자리 이상 20자리 이하로 설정해주세요."
        });
    }

    pool.getConnection(function(error,connection){
        if(error){
            if(typeof connection !== 'undefined'){
                connection.release();
            }
            next(error);
        } else{
            var queryString = squel.select({seperator:"\n"})
                                   .from('user')
                                   .field('password')
                                   .where('username = ?', req.username)
                                   .where('user_id = ?', req.user_id)
                                   .toString();
            connection.query(queryString, function(error, results, fields){
                if (error){
                    connection.release();
                    next(error);
                } else{
                    var isValid = bcrypt.compareSync(req.body.password, results[0].password);
                    if (isValid){
                        if (req.body.new_password !== req.body.new_password_confirm){
                            connection.release();
                            res.status(401).json({
                                status: "새로운 비밀번호와 비밀번호 확인이 일치하지 않습니다.",

                            });
                        } else{
                            if (req.body.password === req.body.new_password){
                                connection.release();
                                res.status(401).json({
                                    status: "새로운 비밀번호를 현재 비밀번호와 다르게 설정하세요."
                                });
                            } else{
                                connection.beginTransaction(function(error){
                                    if(error){
                                        connection.release();
                                        next(error);
                                    }
                                    var newPwHashed = bcrypt.hashSync(req.body.new_password, parseInt(process.env.SALT_ROUNDS));
                                    var changeQuery = squel.update({seperator:"\n"})
                                                        .table('user')
                                                        .set('password', newPwHashed)
                                                        .where('username = ?', req.username)
                                                        .where('user_id = ?', req.user_id)
                                                        .toString();
                                    connection.query(changeQuery, function(error, results, fields){
                                        if (error){
                                            return connection.rollback(function(){
                                                connection.release();
                                                next(error);
                                            });
                                        } else {
                                            var deleteString = squel.delete({separator:'\n'})
                                                                    .from('user')
                                                                    .where('password = ?', bcrypt.hashSync(req.body.password, parseInt(process.env.SALT_ROUNDS)))
                                                                    .toString();
                                            connection.query(deleteString, function(error, results, fields){
                                                if(error){
                                                    return connection.rollback(function(){
                                                        connection.release();
                                                        next(error);
                                                    });
                                                }
                                                connection.commit(function(error){
                                                    if(error){
                                                        return connection.rollboack(function(){
                                                            connection.release();
                                                            next(error);
                                                        });
                                                    }
                                                    res.status(200).json({
                                                        message: "비밀번호가 성공적으로 변경되었습니다."
                                                    });
                                                });
                                            });
                                        }
                                    });
                                });
                                
                            }
                        }
                    } else{
                        connection.release();
                        res.status(401).json({
                            message: '입력하신 비밀번호가 일치하지 않습니다'
                        });
                    }
                }
            });
        }
    });
});


// [admin] login
router.post('/admin/login', function(req, res, next){
    if (!req.body.admin_username || !req.body.admin_password){
        res.status(401).json({
            error_message: "REQUIRED FIELDS : (admin_username, admin_password)",
            user_error_message: "필수 항목을 모두 입력하십시오."
        });
    }
    else if(req.body.admin_username.length > 20 || req.body.admin_username.length < 4 || req.body.admin_password.length > 20 ||  req.body.admin_password.length < 4){
        res.status(401).json({
            error_type: "Data Integrity Violation",
            error_message: "입력하신 파라미터 글자 숫자를 참고하세요: admin_username(4~20), password(4~20)"
        });
    }
    else{
        pool.getConnection(function(error, connection){
            if(error){
                if(typeof connection !== 'undefined'){
                    connection.release();
                }
                next(error);
            }
            else{
                var queryString = squel.select({separator: "\n"})
                                    .from('admin')
                                    .field('admin_id')
                                    .field('admin_password')
                                    .field('admin_name')
                                    .where('admin_username = ?', req.body.admin_username)
                                    .toString();
                connection.query(queryString, function(error, results, fields){
                    connection.release();
                    if (error){
                        next(error);
                    } 
                    else {
                        if (!!results[0]){
                            var password_stored = results[0].admin_password;
                            var passwordIsValid = bcrypt.compareSync(req.body.admin_password, password_stored);
                            if (passwordIsValid){
                                jwt.sign({admin_id: results[0].admin_id, admin_username: req.body.admin_username, admin_name: results[0].admin_name}, process.env.ADMIN_SECRET_KEY, {expiresIn: '7d'}, function(error, token){
                                    if (error){
                                        next(error);
                                    }
                                    else{
                                    res.status(200).json({
                                        auth: true,
                                        token: token
                                    });
                                    }
                                });
                            }
                            else{
                                res.status(401).json({
                                    status: "id / 비밀번호가 일치 하지 않습니다.",
                                    auth: false,
                                    token: null
                                });
                            }
                        }
                        else{
                            res.status(401).json({
                                status: "해당 아이디가 존재 하지 않습니다.",
                                auth: false,
                                token: null
                            });
                        }
                    }
                });
            }
        });
    }
});


// [admin] registration
router.post('/admin/register', function(req, res, next){

    if(!req.body.admin_username || !req.body.admin_password ||  !req.body.admin_name){
        res.status(401).json({
            error_message: "REQUIRED FIELDS : (admin_username, admin_password, admin_name)",
            user_error_message: "필수 항목을 모두 입력하십시오."
        });
    }else if(req.body.admin_username.length < 4 || req.body.admin_username.length > 20 ||
        req.body.admin_password.length < 4 || req.body.admin_password.length > 20){
        res.status(401).json({
            error_type: "Data Integrity Violation",
            error_message: "입력하신 파라미터 글자 숫자를 참고하세요: admin_username(4~20), admin_password(4~20), admin_phone(~20), admin_email(~30)"
        });
    }

    pool.getConnection(function(error, connection){
        if(error){
            if(typeof connection !== 'undefined'){
                connection.release();
            }
            next(error);
        } else{
            var selectString = squel.select({separator:'\n'})
                                    .from('admin')
                                    .field('admin_username')
                                    .where('admin_username = ?', req.body.admin_username)
                                    .toString();
            connection.query(selectString, function(error, results, fields){
                if(error){
                    connection.release();
                    next(error);
                }
                if(Array.isArray(results) && !!results.length){
                    if(req.body.admin_username === results[0].admin_username){
                        connection.release();
                        res.status(401).json({
                            error_message: "이미 사용중인 username입니다."
                        });
                    }
                }
                else {
                    connection.beginTransaction(function(error){
                        if (error){
                            connection.release();
                            next(error);
                        }
                        var hashedPassword = bcrypt.hashSync(req.body.admin_password, parseInt(process.env.SALT_ROUNDS));
                        var registerString = squel.insert({separator:"\n"})
                                                .into('admin')
                                                .set('admin_username', req.body.admin_username)
                                                .set('admin_password', hashedPassword)
                                                .set('admin_name', req.body.admin_name)
                                                .toString();
                        connection.query(registerString, function(error, results, fields){
                            if(error){
                                return connection.rollback(function() {
                                    connection.release();
                                    next(error);
                                });
                            }
        
                            var requestString = squel.select({seperator:"\n"})
                                                    .from('admin')
                                                    .field('admin_username')
                                                    .field('admin_name')
                                                    .where('admin_id = ?', results.insertId)
                                                    .toString();
                            
                            connection.query(requestString, function(error, results, fields){ 
                                if (error){
                                    return connection.rollback(function() {
                                        connection.release();
                                        next(error);
                                    });
                                }
                                if (!!results) {
                                    jwt.sign({admin_username: results[0].admin_username, 
                                    admin_id: results.insertId, admin_name: results[0].admin_name},
                                    process.env.ADMIN_SECRET_KEY, {expiresIn: '7d'}, 
                                    function(error, token){
                                        if (error){
                                            return connection.rollback(function(){
                                                connection.release();
                                                next(error);
                                            });
                                        }
                                        connection.commit(function(error){
                                            if (error){
                                                return connection.rollback(function(){
                                                    connection.release();
                                                    next(error);
                                                });
                                            }
                                            connection.release();
                                            res.status(200).json({
                                                message: "회원가입이 완료되었습니다.",
                                                auth: true,
                                                token: token
                                            });
                                        });
                                    });
                                } else{
                                    connection.release();
                                    res.status(401).json({
                                        message: "Internal Server Error: Registration Failed"
                                    });
                                }   
                            });
                        });
                    });
                }
            });
        }
    });
});


// [admin] change password
router.put('/admin/change_password', verifyAdminToken, function(req, res, next){
    /*
    {
        "admin_password": (current admin password)
        "new_password":
        "new_password_confirm"
    }
    */

    if(!req.body.admin_password){
        res.status(401).json({
            error_message: "REQUIRED FIELD admin_password not entered",
            user_error_message: "운영자 비밀번호가 입력되지 않았습니다."
        });
    }
    if(!req.body.new_password || !req.body.new_password_confirm){
        res.status(401).json({
            error_message: "REQUIRED FIELDS: (new_password, new_password_confirm)",
            user_error_message: "새로운 비밀번호와 비밀번호확인을 입력해주십시오."
        });
    }
    if(req.body.new_password.length < 4 || req.body.new_password.length > 20){
        res.status(401).json({
            error_type: "Date Integrity Violation",
            error_message: "비밀번호는 4자리 이상 20자리 이하로 설정해주세요."
        });
    }

    pool.getConnection(function(error, connection){
        if(error){
            if(typeof connection !== 'undefined'){
                connection.release();
            }
            next(error);
        } else{
            var queryString = squel.select({seperator:"\n"})
                                   .from('admin')
                                   .field('admin_password')
                                   .where('admin_id = ?', req.admin_id)
                                   .toString();
            connection.query(queryString, function(error, results, fields){
                if (error){
                    connection.release();
                    res.status(500).json({
                        message: error.message,
                        stack: error.stack
                    });
                } else{
                    var isValid = bcrypt.compareSync(req.body.admin_password, results[0].admin_password);
                    if (isValid){
                        if (req.body.new_password !== req.body.new_password_confirm){
                            connection.release();
                            res.status(401).json({
                                status: "새로운 비밀번호와 비밀번호확인이 일치하지 않습니다.",

                            });
                        } else{
                            if (req.body.admin_password === req.body.new_password){
                                connection.release();
                                res.status(401).json({
                                    status: "새로운 비밀번호를 현재 비밀번호와 다르게 설정하세요."
                                });
                            } else{
                                connection.beginTransaction(function(error){
                                    if(error){
                                        connection.release();
                                        next(error);
                                    }
                                    var newPwHashed = bcrypt.hashSync(req.body.new_password, parseInt(process.env.SALT_ROUNDS));
                                    var changeQuery = squel.update({seperator:"\n"})
                                                        .table('admin')
                                                        .set('admin_password', newPwHashed)
                                                        .where('admin_id = ?', req.admin_id)
                                                        .toString();
                                    connection.query(changeQuery, function(error, results, fields){
                                        if (error){
                                            return connection.rollback(function(){
                                                connection.release();
                                                next(error);
                                            });
                                        } else {
                                            var deleteString = squel.delete({separator:'\n'})
                                                                    .from('admin')
                                                                    .where('admin_password = ?', bcrypt.hashSync(req.body.admin_password, parseInt(process.env.SALT_ROUNDS)))
                                                                    .toString();
                                            connection.query(deleteString, function(error, results, fields){
                                                if(error){
                                                    return connection.rollback(function(){
                                                        connection.release();
                                                        next(error);
                                                    });
                                                } else {
                                                    connection.commit(function(error){
                                                        if(error){
                                                            return connection.rollback(function(){
                                                                connection.release();
                                                                next(error);
                                                            });
                                                        } else {
                                                            res.status(200).json({
                                                                message: "비밀번호가 성공적으로 변경되었습니다."
                                                            });
                                                        }
                                                    });
                                                }
                                            });
                                        }
                                });
                                
                                });
                            }
                        }
                    } else{
                        connection.release();
                        res.status(401).json({
                            message: '입력하신 비밀번호가 일치하지 않습니다.'
                        });
                    }
                }
            });
        }
    });
});


// [admin] create service
router.post('/admin/create_service', verifyAdminToken, function(req, res, next){
    /*
    json format
    {
	"user_id":10,
	"service_name":"Homepage",
	"service_start_date":"2018-06-14 12:12:56",
	"service_end_date":"2018-06-15 16:12:56",
	"service_details_content":[{"service_details_content":"service details row 1"},
		{"service_details_content":"service details row 2"},
		{"service_details_content":"service details row 3"}
	]
}
    */
    if(!req.body.user_id || !req.body.service_name || !req.body.service_start_date || !req.body.service_end_date){
        res.status(401).json({
            error_message: "REQUIERED FIELDS : (user_id, service_name, service_start_date, service_end_date)"
        });
    } else {
        pool.getConnection(function(error, connection){
            if(error){
                if(typeof connection !== 'undefined'){
                    connection.release();
                }
                next(error);
            } else {
                connection.beginTransaction(function(error){
                    if(error){
                        connection.release();
                        next(error);
                    } else {
                        var insertString = squel.insert({separator:'\n'})
                                                .into('service')
                                                .set('user_id', req.body.user_id)
                                                .set('service_name', req.body.service_name)
                                                .set('service_start_date', req.body.service_start_date)
                                                .set('service_end_date', req.body.service_end_date)
                                                .toString();
                        connection.query(insertString, function(error, results, fields){
                            if(error){
                                return connection.rollback(function(){
                                    connection.release();
                                    next(error);
                                });
                            } else {
                                var contents = req.body.service_details_content;

                                for(var i = 0; i < contents.length; i++){
                                    contents[i].service_id = results.insertId;
                                }

                                var insertString = squel.insert({separator:'\n'})
                                                        .into('service_details')
                                                        .setFieldsRows(contents)
                                                        .toString();
                                connection.query(insertString, function(error, results, fields){
                                    if(error){
                                        return connection.rollback(function(){
                                            connection.release();
                                            next(error);
                                        });
                                    } else {
                                        connection.commit(function(error){
                                            if(error){
                                                return connection.rollback(function(){
                                                    connection.release();
                                                    next(error);
                                                });
                                            }
                                            connection.release();
                                            res.status(200).json({
                                                message: "해당 서비스가 성공적으로 추가되었습니다."
                                            })
                                        });
                                    }
                                });
                            }
                        });
                    }
                });
            }
        });
    }
});


// [admin] delete service
router.delete('/admin/delete_service', verifyAdminToken, function(req, res, next){
    if(!req.body.service_id){
        res.status(401).json({
            error_message: "service_id를 입력하십시오."
        });
    }

    pool.getConnection(function(error, connection){
        if(error){
            if(typeof connection !== 'undefined'){
                connection.release();
            }
            next(error);
        } else {
            connection.beginTransaction(function(error){
                if(error){
                    return connection.rollback(function(){
                        connection.release();
                        next(error);
                    });
                } else {
                    var deleteString = squel.delete({separator:'\n'})
                                            .from('service_details')
                                            .where('service_id = ?', req.body.service_id)
                                            .toString();
                    connection.query(deleteString, function(error, results, fields){
                        if(error){
                            return connection.rollback(function(){
                                connection.release();
                                error.query_index = 0;
                                next(error);
                            });
                        } else {
                            var deleteString = squel.delete({separator:'\n'})
                                                    .from('service')
                                                    .where('service_id = ?', req.body.service_id)
                                                    .toString();
                            connection.query(deleteString, function(error, results, fields){
                                if(error){
                                    return connection.rollback(function(){
                                        connection.release();
                                        error.query_index = 1;
                                        next(error);
                                    });
                                } else {
                                    connection.commit(function(error){
                                        if(error){
                                            connection.rollback(function(){
                                                connection.release();
                                                error.type = "commit error";
                                                next(error);
                                            });
                                        } else {
                                            res.status(200).json({
                                                message: "성공적으로 해당 서비스를 삭제하였습니다."
                                            });
                                        }
                                    });
                                }
                            });
                        }
                    });
                }
            });
        }
    });
});


// [admin] add service details by service_id
router.post('/admin/add_service_details', verifyAdminToken, function(req, res, next){
    if(!req.body.service_id || !req.body.service_details_content){
        res.status(401).json({
            error_message: "REQUIRED FEILDS: (service_id, service_details_content)"
        });
    } else {
        pool.getConnection(function(error, connection){
            if(error){
                if(typeof connection !== 'undefined'){
                    connection.release();
                }
                next(error);
            } else {
                var contents = req.body.service_details_content;

                for(var i = 0; i < contents.length; i++){
                    contents[i].service_id = req.body.service_id; 
                }

                var insertString = squel.insert({separator:'\n'})
                                        .into('service_details')
                                        .setFieldsRows(req.body.service_details_content)
                                        .toString();
                connection.query(insertString, function(error, results, fields){
                    connection.release();
                    if(error){
                        next(error);
                    } else {
                        res.status(200).json({
                            message: "성공적으로 서비스 정보를 추가했습니다."
                        });
                    }
                });
            }
        });
    }
});


// [admin] fetch all service_details for a service
router.get('/admin/service_details/:service_id', verifyAdminToken, function(req, res, next){
    if(!req.params){
        res.status(401).json({
            error_message: "req.params is empty"
        });
    }
    pool.getConnection(function(error, connection){
        if(error){
            if(typeof connection !== 'undefined'){
                connection.release();
            }
            next(error);
        } else {
            var selectString = squel.select({separator:'\n'})
                                    .from('service_details')
                                    .field('service_details_id')
                                    .field('service_id')
                                    .field('service_details_content')
                                    .where('service_id =?', req.params.service_id)
                                    .toString();
            connection.query(selectString, function(error, results, fields){
                connection.release();
                if(error){
                    next(error);
                } else {
                    res.status(200).json({
                        message: "성공적으로 요청하신 서비스에 해당하는 서비스 정보를 가져왔습니다.",
                        results
                    });
                }
            });
        }
    });
});


// [admin] delete service details by service_details_id
router.delete('/admin/delete_service_details', verifyAdminToken, function(req, res, next){
    if(!req.body.service_details_id){
        res.status(401).json({
            error_message: "REQUIRED FIELDS: (service_details_id)"
        });
    }
    pool.getConnection(function(error, connection){
        if(error){
            if(typeof connection !== 'undefined'){
                connection.release();
            }
            next(error);
        } else {
            var deleteString = squel.delete({separator:'\n'})
                                    .from('service_details')
                                    .where('service_details_id = ?', req.body.service_details_id)
                                    .toString();
            connection.query(deleteString, function(error, results, fields){
                connection.release();
                if(error){
                    next(error);
                } else {
                    res.status(200).json({
                        message: "해당 서비스 정보를 삭제했습니다."
                    });
                }
            });
        }
    });
});


// [admin] request payment
router.post('/admin/request_payment', verifyAdminToken, function(req, res, next){
    if(!req.body.service_id || !req.body.payment_amount){
        res.status(401).json({
            error_message: "REQUIRED FIELDS: (service_id, payment_amount)"
        });
    } else {
        pool.getConnection(function(error, connection){
            if(error){
                if(typeof connection !== 'undefined'){
                    connection.release();
                }
                next(error);
            } else {
                var selectString = squel.select({separator:'\n'})
                                        .from('service')
                                        .field('user_id')
                                        .field('service_name')
                                        .field('service_start_date')
                                        .field('service_end_date')
                                        .field('service_details')
                                        .where('service_id = ?', req.body.service_id)
                                        .toString();
                connection.query(selectString, function(error, results, fields){
                    if(error){
                        connection.release();
                        next(error);
                    } else {
                        var insertString = squel.insert({separator:'\n'})
                                            .into('service_payment')
                                            .set('service_id', req.body.service_id)
                                            .set('payment_amount', req.body.payment_amount)
                                            .set('payment_description', req.body.payment_description)
                                            .toString();
                        connection.query(insertString, function(error, results, fields){
                            connection.release();
                            if(error){
                                next(error);
                            } else {
                                res.status(200).json({
                                    message: "해당 청구요청이 성공적으로 등록되었습니다."
                                });
                            }
                        });
                    }
                    
                });
            }
        });
    }
});


// [user] make payment (need to incorporate payment module later)
router.put('/api/make_payment', verifyToken, function(req, res, next){
    if(!req.body.payment_id || !req.body.service_id || !req.body.payment_amount){
        res.status(401).json({
            error_message: "REQUIRED FIELDS: (payment_id, service_id, payment_amount)"
        });
    }
    pool.getConnection(function(error, connection){
        if(error){
            if(typeof connection !== 'undefined'){
                connection.release();
            }
            next(error);
        } else {
            var selectString = squel.select({separator:'\n'})
                                    .from('service_payment')
                                    .field('payment_amount')
                                    .where('payment_id = ?', req.body.payment_id)
                                    .where('service_id = ?', req.body.service_id)
                                    .toString();
            connection.query(selectString, function(error, results, fields){
                if(error){
                    connection.release();
                    error.query_index = 0;
                    next(error);
                } else {
                    var selectString = squel.select({separator:'\n'})
                                            .from('service')
                                            .field('user_id')
                                            .where('service_id = ?', req.body.service_id)
                                            .toString();
                    connection.query(selectString, function(error, select_results, fields){
                        if(error){
                            connection.release();
                            error.query_index = 1;
                            next(error);
                        } else {
                            var selectString = squel.select({separator:'\n'})
                                                    .from('service_payment')
                                                    .field('payment_amount')
                                                    .where('payment_id = ?', req.body.payment_id)
                                                    .toString();
                            connection.query(selectString, function(error, results, fields){
                                if(error){
                                    connection.release();
                                    error.query_index = 2;
                                    next(error);
                                } else {
                                    if(req.user_id === select_results[0].user_id){ // request is from valid user
                                        var paymentLeftover = parseInt(results[0].payment_amount, 10) - parseInt(req.body.payment_amount, 10);
                                        if(paymentLeftover >= 0){
                                            var updateString = squel.update({separator:'\n'})
                                                                    .table('service_payment')
                                                                    .set('payment_amount', paymentLeftover)
                                                                    .where('payment_id = ?', req.body.payment_id)
                                                                    .toString();
                                            connection.query(updateString, function(error, results, fields){
                                                if(error){
                                                    connection.release();
                                                    error.query_index = 3;
                                                    next(error);
                                                } else {
                                                    if(pyamentLeftover > 0){
                                                        connection.release();
                                                        res.status(200).json({
                                                            message: "대금 지급이 성공적으로 이뤄졌습니다. 앞으로 " + paymentLeftover + "원만 지급하시면 됩니다."
                                                        });
                                                    } else {
                                                        connection.release();
                                                        res.status(200).json({
                                                            message: "대금이 성공적으로 완납되었습니다. 감사합니다."
                                                        });
                                                    }
                                                }
                                            });
                                        } else { // over-payment
                                            connection.release();
                                            res.status(401).json({
                                                error_message: "내실 대금보다 많은 금액을 입력하셨습니다. 대금과 같거나 적은 금액을 입력하십시오."
                                            });
                                        }
                                    } else { // request is from invalid user
                                        connection.release();
                                        next(error);
                                    }
                                }
                            });
                        }
                    });
                }
            });
        }
    });
});


// [admin] looks up user by user_id
router.get('/admin/search_user_id/:user_id', verifyAdminToken, function(req, res, next){	
	pool.getConnection(function(error,connection){
		if(error){
			if(typeof connection !== 'undefined'){
				connection.release();
			}
			error.type = "pool.getConnection";
			error.path = "GET /admin/search_user_id/:user_id";
			error.identity = "[ADMIN]" + req.admin_id;
			error.time = getDateString();
			error.status = 500;
			error.display_message = "데이터베이스상의 문제로 작업이 취소되었습니다. 서버 과부하로 걸린 문제일 수 있으니, 잠시 후 다시 시도해주시기 바랍니다."
			next(error);
		}
		else{
			var selectString = squel.select({separator:"\n"})
								   .from('user')
								   .field('user_full_name')
								   .field('user_id')
								   .field('user_phone')
								   .where('admin_id = ?', req.admin_id)
								   .where('user_id = ?', req.params.user_id)
								   .toString();
			connection.query(selectString, function(error, results, fields){
				connection.release();
				if (error) {	
					error.type = "connection.query"
					error.path = "GET /admin/search_user_id/:user_id";
					error.identity = "[ADMIN]" + req.admin_id;
					error.time = getDateString();
					error.status = 500;
					error.display_message = "서버 문제로 에러가 발생하였습니다."
					error.query_index = 1;
					next(error);
				} 
				else {
					if(results[0]){
						res.status(200).json({
								message: "해당 유저를 성공적으로 불러왔습니다.",
								result: results
							})
					}
					else{
						res.status(200).json({
							message: '해당 유저가 존재하지 않거나 해당 관리자가 관리하는 유저가 아닙니다.'
						});
					}
				}
			});
		}
	});
});


// [admin] looks up user by username
router.get('/admin/search_username/:username', verifyAdminToken, function(req, res, next){	
	pool.getConnection(function(error,connection){
		if(error){
			if(typeof connection !== 'undefined'){
				connection.release();
			}
			error.type = "pool.getConnection";
			error.path = "GET /admin/search_username/:username";
			error.identity = "[ADMIN]" + req.admin_id;
			error.time = getDateString();
			error.status = 500;
			error.display_message = "데이터베이스상의 문제로 작업이 취소되었습니다. 서버 과부하로 걸린 문제일 수 있으니, 잠시 후 다시 시도해주시기 바랍니다."
			next(error);
		}
		else{
			var selectString = squel.select({separator:"\n"})
								   .from('user')
								   .field('user_full_name')
								   .field('username')
								   .field('user_phone')
								   .where('admin_id = ?', req.admin_id)
								   .where('username = ?', req.params.username)
								   .toString();
			connection.query(selectString, function(error, results, fields){
				connection.release();
				if (error) {	
					error.type = "connection.query"
					error.path = "GET /admin/search_username/:username";
					error.identity = "[ADMIN]" + req.admin_id;
					error.time = getDateString();
					error.status = 500;
					error.display_message = "서버 문제로 에러가 발생하였습니다."
					error.query_index = 1;
					next(error);
				} 
				else {
					if(results[0]){
						res.status(200).json({
								message: "해당 유저를 성공적으로 불러왔습니다.",
								result: results
							})
					}
					else{
						res.status(200).json({
							message: '해당 유저가 존재하지 않거나 해당 관리자가 관리하는 유저가 아닙니다.'
						});
					}
				}
			});
		}
	});
});


// [user] views all the services the user signed up for
router.get('/api/view_services', verifyToken, function(req, res, next){
    pool.getConnection(function(error, connection){
        if(error){
            if(typeof connection !== 'undefined'){
                connection.release();
            }
            next(error);
        } else {
            var selectString = squel.select({separator:'\n'})
                                    .from('service')
                                    .left_join('service_details', null, 'service.service_id = service_details.service_id')
                                    .field('service.service_id')
                                    .field('user_id')
                                    .field('service_name')
                                    .field('service_start_date')
                                    .field('service_end_date')
                                    .field('service_details_content')
                                    .where('user_id = ?', req.user_id)
                                    .toString();
            connection.query(selectString, function(error, results, fields){
                connection.release();
                if(error){
                    next(error);
                } else {
                    res.status(200).json({
                        message: "서비스 내용을 성공적으로 불러왔습니다.",
                        results
                    });
                }
            });
        }
    });
});


// [admin] views all the servies a user signed up for
router.get('/admin/view_services/:user_id', verifyAdminToken, function(req, res, next){
    pool.getConnection(function(error, connection){
        if(error){
            if(typeof connection !== 'undefined'){
                connection.release();
            }
            next(error);
        } else {
            var selectString = squel.select({separator:'\n'})
                                    .from('service')
                                    .left_join('service_details', null, 'service.service_id = service_details.service_id')
                                    .field('service.service_id')
                                    .field('user_id')
                                    .field('service_name')
                                    .field('service_start_date')
                                    .field('service_end_date')
                                    .field('service_details_content')
                                    .where('user_id = ?', req.params.user_id)
                                    .toString();
            connection.query(selectString, function(error, results, fields){
                connection.release();
                if(error){
                    next(error);
                } else {
                    res.status(200).json({
                        message: "해당 유저의 서비스정보를 성공적으로 가져왔습니다.",
                        results
                    });
                }
            });
        }
    });
});


/********************************************
*********************************************
***************	핫라인 **********************
*********************************************
********************************************/

// [user] fetches all messages
router.get('/api/hotline', verifyToken, function(req, res, next){
    pool.getConnection(function(error, connection){
		if (error) {
			if (typeof connection !== 'undefined'){
				connection.release();
			}
			error.type = "pool.getConnection";
			error.path = "GET /api/hotline";
			error.identity = "[USER]" + req.user_id;
			error.time = getDateString();
			error.status = 500;
			error.display_message = "데이터베이스상의 문제로 작업이 취소되었습니다. 서버 과부하로 걸린 문제일 수 있으니, 잠시 후 다시 시도해주시기 바랍니다. <br/> 문의 전화: 02-540-7912 이메일: codingbabyfood@gmail.com"
			next(error);
		}
		else {
			var basicString = squel.select({separator:"\n"})
								   .from('user')
                                   .field('user_id')
                                   .field('admin_id')
                                   .where('username = ?', req.username)
								   .toString();
			connection.query(basicString, function(error, base_results, fields){
				if (error) {
					connection.release();
					error.type = "connection.query"
					error.path = "GET /api/hotline";
					error.identity = "[USER]" + req.user_id;
					error.time = getDateString();
					error.status = 500;
					error.display_message = "서버 문제로 에러가 발생하였습니다. 빠른 시일내로 조치하도록 하겠습니다. 문의 전화: 02-540-7912 이메일: codingbabyfood@gmail.com"
					error.query_index = 1;
					next(error);
                }
				else {
					if (base_results[0]) {
                        var queryString = squel.select({separator:'\n'})
								                .from('hotline_message')
                                                .field('user_id')
                                                .field('admin_id')
                                                .field('message_content')
                                                .field('is_from_user')
                                                .field('date_published')
                                                .field('is_read')			
                                                .where('user_id = ?', base_results[0].user_id)
                                                .where('admin_id = ?', base_results[0].admin_id)
                                                .order('date_published', true)
                                                .toString();
						connection.query(queryString, function(error, results, fields){
							if (error) {
								connection.release();
								error.type = "connection.query"
								error.path = "GET /api/hotline";
								error.identity = "[USER]" + req.user_id;
								error.time = getDateString();
								error.status = 500;
								error.display_message = "서버 문제로 에러가 발생하였습니다. 빠른 시일내로 조치하도록 하겠습니다. 문의 전화: 02-540-7912 이메일: codingbabyfood@gmail.com"
								error.query_index = 2;
								next(error);
							} 
							else {
								if(results[0]){
									var updateString = squel.update()
															.table('hotline_message')
															.set('is_read', 1)
															.where('user_id = ?', results[0].user_id)
															.where('admin_id = ?', results[0].admin_id)
															.where('is_from_user = ?', 0)
															.where('is_read = ?', 0)
															.toString();
									
									connection.query(updateString, function(error, results_update, fields){
										connection.release();
										if (error) {
											error.type = "connection.query"
											error.path = "GET /api/hotline";
											error.identity = "[USER]" + req.user_id;
											error.time = getDateString();
											error.status = 500;
											error.display_message = "서버 문제로 에러가 발생하였습니다. 빠른 시일내로 조치하도록 하겠습니다. 문의 전화: 02-540-7912 이메일: codingbabyfood@gmail.com"
											error.query_index = 3;
											next(error);
										} 
										else {
											if(results_update.affectedRows > 0){
												res.status(200).json({
													message: "핫라인메세지들을 성공적으로 불러왔고 1개 이상의 안읽은 메세지를 읽음표시하였습니다.",
													result : results,
													result_update : results_update.affectedRows
													
													
												});
											} else {
												res.status(200).json({
													message: "핫라인메세지들을 성공적으로 불러왔고, 이미 모든 메세지가 읽음 표시 되어있습니다. 새로운 메세지가 없습니다.",
													result : results,
													result_update: 0
													
												});
											}
											
										}
									});
								}
								else{
									connection.release();
									res.status(200).json({
										message: '해당유저에게는 현재 등록 되어있는 핫라인 메세지가 없습니다.',
										result: results
									});	
								}
								
							}
						});
					}
					else{
						connection.release();
						res.status(200).json({
							message: "치명적 에러입니다. 유저가 token assign받고 들어와서 활동하는데 유저를 관리하는 관리자가 없습니다."
						});
					}
				}
			});
		}
	});
});


// [user] writes hotline message
router.post('/api/hotline', verifyToken, function(req, res, next){
	if(req.body.message_content == undefined){
		res.status(401).json({
			error_message: "REQUIRED FIELDS : (message_content)",
			display_message: "필수 항목을 모두 입력하십시오."
		});
	}
	else{
		pool.getConnection(function(error, connection){
			if(error){
				if(typeof connection !== 'undefined'){
					connection.release();
				}
				error.type = "pool.getConnection";
				error.path = "POST /api/hotline";
				error.identity = "[USER]" + req.user_id;
				error.time = getDateString();
				error.status = 500;
				error.display_message = "데이터베이스상의 문제로 작업이 취소되었습니다. 서버 과부하로 걸린 문제일 수 있으니, 잠시 후 다시 시도해주시기 바랍니다. <br/> 문의 전화: 02-540-7912 이메일: codingbabyfood@gmail.com"
				next(error);
			}
			else{
				var queryString = squel.select({separator: "\n"})
									.from('user')
									.field('user_id')
									.field('admin_id')
									.where('user.username = ?', req.username)
									.toString();
				connection.query(queryString, function(error, results, fields){
				if (error) {
					connection.release();
					error.type = "connection.query"
					error.path = "POST /api/hotline";
					error.identity = "[USER]" + req.user_id;
					error.time = getDateString();
					error.status = 500;
					error.display_message = "서버 문제로 에러가 발생하였습니다. 빠른 시일내로 조치하도록 하겠습니다. 문의 전화: 02-540-7912 이메일: codingbabyfood@gmail.com"
					error.query_index = 1;
					next(error);
				} 
				else {
					if(results[0]){
						var date_published = getDateString();
						var postString = squel.insert({separator: "\n"})
										    	.into('hotline_message')
                                                .set('admin_id', results[0].admin_id)
                                                .set('user_id', results[0].user_id)
                                                .set('message_content', req.body.message_content)
                                                .set('is_from_user', 1)
                                                .set('is_read', 0)
                                                .set('date_published', date_published)
                                                .toString();
						connection.query(postString, function(error, results_message, fields){
							connection.release();
							if (error) {
								error.type = "connection.query"
								error.path = "POST /api/hotline";
								error.identity = "[USER]" + req.user_id;
								error.time = getDateString();
								error.status = 500;
								error.display_message = "서버 문제로 에러가 발생하였습니다. 빠른 시일내로 조치하도록 하겠습니다. 문의 전화: 02-540-7912 이메일: codingbabyfood@gmail.com"
								error.query_index = 2;
								next(error);
							} 
							else {
								res.status(201).json({
									message: '핫라인 메세지를 성공적으로 등록하였습니다.',
									results: results_message
								});
							}	
						});
					}
					else{
						connection.release();
						res.status(401).json({
							message: "잘못된 api call; 담당 관리자가 정해지지 않은 상태에서 api call을 하였습니다."
						})
					}
					
				}
				});
			}
		});
	}
});


// [admin] writes user a hotline message
router.post('/admin/hotline', verifyAdminToken, function(req, res, next){
if(!req.body.user_id || !req.body.message_content){
        res.status(401).json({
            error_message: "REQUIRED FIELD: (user_id, message_content)",
            display_message: "필수 항목을 모두 입력해주십시오."
        });
    }
    else {
        pool.getConnection(function(error, connection){
            if(error){
                if(typeof connection !== 'undefined'){
					connection.release();
				}
				error.type = "pool.getConnection";
				error.path = "POST /api/hotline";
				error.identity = "[ADMIN]" + req.admin_id;
				error.time = getDateString();
				error.status = 500;
				error.display_message = "데이터베이스상의 문제로 작업이 취소되었습니다. 서버 과부하로 걸린 문제일 수 있으니, 잠시 후 다시 시도해주시기 바랍니다. <br/> 문의 전화: 02-540-7912 이메일: codingbabyfood@gmail.com"
				next(error);
            } else {
                var date_published = getDateString();
                var postString = squel.insert({separator:'\n'})
                                        .into('hotline_message')
                                        .set('user_id', req.body.user_id)
                                        .set('admin_id', req.admin_id)
                                        .set('is_from_user', 0)
                                        .set('date_published', date_published)
                                        .set('is_read', 0)
                                        .set('message_content', req.body.message_content)
                                        .toString();
                connection.query(postString, function(error, results_message, fields){
                    connection.release();
                    if(error){
                        error.type = "connection.query"
						error.path = "POST /api/hotline";
						error.identity = "[USER]" + req.user_id;
						error.time = getDateString();
						error.status = 500;
                        error.display_message = "서버 문제로 에러가 발생하였습니다. 빠른 시일내로 조치하도록 하겠습니다. 문의 전화: 02-540-7912 이메일: codingbabyfood@gmail.com"
                        error.query_index = 2;
                        next(error);
                    } else {
                        res.status(201).json({
                            message: '핫라인 메세지를 성공적으로 등록하였습니다.',
							results: results_message
                        });
                    }
                });
            }
        });
    }
});


router.use(function(error, req, res, next){   
    
    next(error);
    
});




function verifyToken(req, res, next){
    var bearerHeader = req.headers['authorization'];
    if (typeof bearerHeader !== 'undefined'){
        var bearer = bearerHeader.split(" ");
        var bearerToken = bearer[1];
        jwt.verify(bearerToken, process.env.USER_SECRET_KEY, function(error, decoded) {      
            if (error){ 
                res.status(403).json({ 
                    auth: false, 
                    token: null
                });  
            }
            else {
                req.user_id = decoded["user_id"];
                req.username = decoded["username"];
                req.user_full_name = decoded["user_full_name"];
                next();
            }
        }); 
    } else {
            res.status(403).json({
            auth:false, 
            token:null
        });
    }
};


function verifyAdminToken(req, res, next){
    var bearerHeader = req.headers['authorization'];
    if (typeof bearerHeader !== 'undefined'){
        var bearer = bearerHeader.split(" ");
        var bearerToken = bearer[1];
        jwt.verify(bearerToken, process.env.ADMIN_SECRET_KEY, function(error, decoded) {
            if (error){
                res.status(403).json({
                    auth: false,
                    token: null
                });
            }
            else {
                req.admin_id = decoded["admin_id"];
                req.admin_username = decoded["admin_username"];
                req.admin_name = decoded["admin_name"];
                next();
            }
        });
    } else {
        res.status(403).json({
            auth: false,
            token: null
        });
    }
};


function getDateString(){
	var dateTimeNow = new Date(Date.now());
	var year = dateTimeNow.getUTCFullYear();
	var month = dateTimeNow.getUTCMonth() + 1;
	var date = dateTimeNow.getUTCDate();

	var hour = dateTimeNow.getUTCHours();
	var minute = dateTimeNow.getUTCMinutes();
	var second = dateTimeNow.getUTCSeconds();
	var dateString = year + "-" + month + "-" + date + " " + hour + ":" + minute + ":" + second;
	return dateString;
}


// numberToMoney(60000) returns "6만원" 
// numberToMoney(60000007000) returns "600억7000원"
function numberToMoney(number) {
    var str = (+number).toString().trim();

    if(str.length <= 4){
        return str + '원';
    }else if(str.length <= 8){
        first_four = (+str.substr(-4)); // unary + removes preceding 0's
        if(first_four == '0'){
            first_four = '';
        }
        str = str.slice(0, -4);
        return str + '만' + first_four + '원';
    }else if(str.length <= 12){
        first_four = (+str.substr(-4));
        if(first_four == '0'){
            first_four = '';
        }
        str = str.slice(0, -4);
        second_four = (+str.substr(-4)) + '만';
        if(second_four == '0만'){
            second_four = '';
        }
        str = str.slice(0, -4);
        return str + '억' + second_four + first_four + '원';
    }else{
        throw new error("The number of digits cannot exceed 12. Try a smaller number");
    }
}

// from zikigo
function getDateSerial(){
    var dateTimeNow = new Date(Date.now());
    var year = dateTimeNow.getFullYear();
    var month = dateTimeNow.getMonth()+1;
    var date = dateTimeNow.getDate();

    var hour = dateTimeNow.getHours();
    var minute = dateTimeNow.getMinutes();
    var second = dateTimeNow.getSeconds();
    return ""+year+month+date+hour+minute+second;
}


module.exports = router;