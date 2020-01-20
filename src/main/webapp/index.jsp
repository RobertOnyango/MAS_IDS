<html>
<head>
<title>Admin Login Page</title>
<link href="webjars/bootstrap/4.3.1/css/bootstrap.min.css" rel="stylesheet">

</head>
<body>

<div class=container>
	<div class = row>
		<div class = "col-md-4 offset-md-4">
		<h2>MultiAgent IDS</h2>
		<h4> Administrator Login </h4>
		
		<form action="submit">
		  <div class="form-group">
		    <label for="username">UserName</label>
		    <input type="text" class="form-control" id="usename" aria-describedby="user" placeholder="Username Admin" value="admin">
		    <small id="Admin" class="form-text text-muted">Security Administrator User name  </small>
		  </div>
		  <div class="form-group">
		    <label for="password">Password</label>
		    <input type="password" class="form-control" id="password" placeholder="Password" value="admin">
		  </div>
		 
		  <button type="submit" class="btn btn-primary">Submit</button>
		</form>
		</div>
	</div>
</div>

<script src="webjars/jquery/3.4.1/jquery.min.js" type="text/javascript"></script>
<script src="webjars/bootstrap/4.3.1/js/bootstrap.min.js" type="text/javascript"></script>
</body>
</html>
