const express = require("express");
const app = express();
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");
const mysql = require("mysql");
const jwt = require("jsonwebtoken");
const http = require("http");

app.use(bodyParser.json());
app.use("/user",verifyAuth);

var con = mysql.createConnection({
  	host: "localhost",
  	user: "root",
  	password: "root",
	database: "blogs"
});

const port = 5000;
const hostname = "localhost";
const jwtSecret = 'fhsfhsguhhsuhushgsuhgusu837587';
app.listen(port, hostname, () => {
  console.log(`Server running at http://${hostname}:${port}/`);
});

app.get('/',function(req,res) {
	console.log('Home page log');
	res.send('Hi welcome to blogs API');	
});
	
var verifyAuth = function (req, res, next) {
  	var token = req.headers.authToken;
	if(!token) {
		res.status(401).send("You are not authorised to access this service!");
	} else {
		let verifyToken = jwt.verify(token,jwtSecret);
		if(verifyToken) {
			next();
		} else {
			res.status(401).send("You sent an wrong authorization, try again!");	
		}
	}
}

app.post('/register', async (req,res) => {
	let{
		firstName,
		lastName,
		email,
		dob,
		password,
		role
	} = req.body;
	if(email) {
		//check if user email already registered on server
		var checkEmail = 'SELECT id FROM users WHERE email = ?';
		con.query(checkEmail, [email], function (err, result) {
		  if (err) throw err;
		  if(result.length) {
		  	res.status(401).send("Email is already registered!");
		  }
		});
		if(firstName && lastName && dob && password && role) {
			password = await bcrypt.hash(password,'dudhwuwwygy');
			var insertNewUser = 'INSERT INTO users (firstName,lastName,email,dob,password,role) VALUES ?';
			var userDetails = [firstName,lastName,email,dob,userType,role];
			con.query(insertNewUser,[userDetails],function(err, insertUserResult) {
				if (err) throw err;
				if(insertUserResult.affectedRows) {
					res.status(200).send("You are successfully registered!");
				}
			});
		}
	}
});
	
app.post('/login', async (req,res) => {
	let{
		email,
		password
	} = req.body;
	if(email && password) {
		var checkEmail = 'SELECT id,password FROM users WHERE email = ?';
		con.query(checkEmail, [email], function (err, result) {
		  if (err) throw err;
		  if(!result) {
		  	res.status(401).send("No user found registered with this email!");
		  } else if(typeof result[0]['password'] !== 'undefined') {
		  	let comparePassword = await bcrypt.compare(password,result[0]['password']);
			if(!comparePassword) {
				res.status(401).send("Your entered a wrong Password! Please try again");
			}
			//user is authenticated share him a jwt token for further verifications
			let userData = {
				userId: result[0]['id'],
				time: Date()
			};
			let token = jwt.sign(userData,jwtSecret);
			res.status(200).send({
				message: "Login Successful",
				token: token
			});
		  }
		});
	}
});

app.post('/user/createBlog', async (req,res) => {
	let {
		blogTitle,
		blogDescription,
		status,
		blogCategory,
		loggedInUserId
	} = req.body;
	if(blogTitle && loggedInUserId) {
		//check if user email already registered on server
		var checkTitle = 'SELECT id FROM blogs WHERE blogTitle = ? AND blogAuthorId = ?';
		con.query(checkTitle, [blogTitle,loggedInUserId], function (err, result) {
		  if (err) throw err;
		  if(result.length) {
		  	res.status(401).send("Blog already exists with the same title!");
		  }
		});
		if(blogDescription && blogCategory) {
			var insertNewBlog = 'INSERT INTO blogs (blogTitle,blogDescription,blogPubDate,blogModDate,status,blogCategory,blogAuthorId) VALUES ?';
			var blogDetails = [blogTitle,blogDescription,Date(),Date(),status,blogCategory,loggedInUserId];
			con.query(insertNewBlog,[blogDetails],function(err, insertBlogResult) {
				if (err) throw err;
				if(insertBlogResult.affectedRows) {
					res.status(200).send("Blog created successfully!");
				}
			});
		}
	}
});

app.post('/user/updateBlog/:id', async(req,res) => {
	let blogId = req.params.id;
	if(blogId) {
		var checkBlog = 'SELECT * FROM blogs WHERE id = ?';
		con.query(checkBlog, [blogId], function (err, result) {
		  if (err) throw err;
		  if(!result) {
		  	res.status(401).send("Blog does not exist with this ID!");
		  } else {
		  		let blogAuthorId = (typeof result[0]['blogAuthorId'] != 'undefined') ? result[0]['blogAuthorId']: 0;
			 	if(blogAuthorId) {
			 		let{
						blogTitle,
						blogDescription,
						status,
						blogCategory,
						loggedInUserId
					} = req.body;
					var isAdmin = false;
					var checkRole = 'SELECT role FROM users WHERE id = ?';
					con.query(checkRole, [loggedInUserId], function (err, roleResult) {
					  if (err) throw err;
					  if(roleResult.length) {
					  	//1 = admin, 2 = normal user
						if(typeof roleResult[0]['role'] != 'undefined' && roleResult[0]['role'] == 1) {
							isAdmin = true;
						}
						if(isAdmin || (blogAuthorId == loggedInUserId)) {
							var updateBlog = "UPDATE blogs SET blogTitle = ?,blogDescription =?,status =?,blogCategory = ?  WHERE id = ?";
							con.query(updateBlog,[blogTitle,blogDescription,status,blogCategory,blogId], function (err, blogResult) {
							    if (err) throw err;
								if(blogResult.affectedRows) {
									res.status(200).send("Blog Updated Successfully");
								}
							});
						} else {
							res.status(401).send("Not authorized");
						}
					  }
					});
			 	}
		  }
		});
	}
});

app.post('/user/deleteBlog/:id', async(req,res) => {
	let blogId = req.params.id;
	if(blogId) {
		var checkBlog = 'SELECT * FROM blogs WHERE id = ?';
		con.query(checkBlog, [blogId], function (err, result) {
		  if (err) throw err;
		  if(!result) {
		  	res.status(401).send("Blog does not exist with this ID!");
		  } else {
		  		let blogAuthorId = (typeof result[0]['blogAuthorId'] != 'undefined') ? result[0]['blogAuthorId']: 0;
			 	if(blogAuthorId) {
			 		let{
						loggedInUserId
					} = req.body;
					var isAdmin = false;
					var checkRole = 'SELECT role FROM users WHERE id = ?';
					con.query(checkRole, [loggedInUserId], function (err, roleResult) {
					  if (err) throw err;
					  if(roleResult.length) {
					  	//1 = admin, 2 = normal user
						if(typeof roleResult[0]['role'] != 'undefined' && roleResult[0]['role'] == 1) {
							isAdmin = true;
						}
						if(isAdmin || (blogAuthorId == loggedInUserId)) {
							var deleteBlog = "DELETE from blogs WHERE id = ?";
							con.query(deleteBlog,[blogId], function (err, blogResult) {
							    if (err) throw err;
								if(blogResult.affectedRows) {
									res.status(200).send("Blog Deleted Successfully");
								}
							});
						} else {
							res.status(401).send("Not authorized");
						}
					  }
					});
			 	}
		  }
		});
	}
});

app.post('/user/blogs', async(req,res) => {
	let{
		loggedInUserId,
		pageNumber,
		categoryId
	} = req.body;
	if(pageNumber == "undefined") {
		pageNumber = 1;
	}
	let isAdmin = false;
	var checkRole = 'SELECT role FROM users WHERE id = ?';
	con.query(checkRole, [loggedInUserId], function (err, roleResult) {
	  if (err) throw err;
	  if(roleResult.length) {
	  	//1 = admin, 2 = normal user
		if(typeof roleResult[0]['role'] != 'undefined' && roleResult[0]['role'] == 1) {
			isAdmin = true;
		}
		var getBlogs = "SELECT blogTitle,blogDescription,blogPubDate from blogs WHERE status = 1";
		if(categoryId) {
			getBlogs += " AND blogCategory = " + categoryId;
		}
		if(!isAdmin) {
			getBlogs += " AND blogAuthorId = " + loggedInUserId;
		}
		let limitPerPage = 10;
		let offset = (pageNumber - 1) * limitPerPage;
		getBlogs += " LIMIT "+limitPerPage+" OFFSET "+offset;
		con.query(getBlogs, function (err, result, fields) {
		    if (err) throw err;
		    res.status(200).send(result);
		});
	  }
	});
});