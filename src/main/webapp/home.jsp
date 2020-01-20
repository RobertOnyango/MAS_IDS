<%@ page language="java" contentType="text/html; charset=ISO-8859-1"
    pageEncoding="ISO-8859-1" isELIgnored="false"%>
<!DOCTYPE html>
<html>
<head>
<meta charset="ISO-8859-1">
<link href="webjars/bootstrap/4.3.1/css/bootstrap.min.css" rel="stylesheet">
<title>MAS_IDS Home Page</title>
</head>
<body>

<nav class="navbar navbar-expand-lg navbar-light bg-light">
  <a class="navbar-brand" href="#">MAS_IDS</a>
  <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNav" aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
    <span class="navbar-toggler-icon"></span>
  </button>
  <div class="collapse navbar-collapse" id="navbarNav">
    <ul class="navbar-nav">
      <li class="nav-item active">
        <a class="nav-link" href="#">Home <span class="sr-only">(current)</span></a>
      </li>
      <li class="nav-item">
        <a class="nav-link" href="rules">Rules</a>
      </li>
      <li class="nav-item">
        <a class="nav-link" href="logs">Logs</a>
      </li>
      <li class="nav-item">
        <a class="nav-link" href="index.jsp" tabindex="-1" aria-disabled="false">Log Out</a>
      </li>
    </ul>
  </div>
</nav>

<h2 class="text-center">Multi-Agent System IDS</h2>

<div class="container">
	<div class="row">
		<div class="col-md-2">
			<form action="start">
				<button type="button" class="btn btn-primary btn-lg btn-disabled">Start the Agents</button>
			</form>
		</div>
		<div class="col-md-4"></div>
		<div class="col-md-4"></div>
		<div class="col-md-2">
		
			<form action="view">
				<button type="submit" class="btn btn-secondary">View Intrusion Reports</button>
			</form>
		</div>
	</div>
</div>

<div class="container">
	<div class="row">
		<div class="col-md-2"></div>
		<div class="col-md-4">
			<div class="panel panel-default">
			  <div class="panel-heading">
			    <h3 class="panel-title">TCP</h3>
			  </div>
			  <div class="panel-body">
			    <b><i>Number of rules triggered versus total rule count of the protocol</i></b>
			    <h4>1 / 1</h4>
			    
			  </div>
			</div>
		</div>
		<div class="col-md-4">
			<div class="panel panel-default">
			  <div class="panel-heading">
			    <h3 class="panel-title">UDP</h3>
			  </div>
			  <div class="panel-body">
			    <b><i>Number of rules triggered versus total rule count of the protocol</i></b>
			    <h4>0 / 0</h4>
			  </div>
			</div>
		</div>
		<div class="col-md-2"></div>
	</div>
</div>
<br><br>
<div class="container">
	<div class="row">
		<div class="col-md-2"></div>
		<div class="col-md-4">
			<div class="panel panel-default">
			  <div class="panel-heading">
			    <h3 class="panel-title">ICMP</h3>
			  </div>
			  <div class="panel-body">
			    <b><i>Number of rules triggered versus total rule count of the protocol</i></b>
			    <h4>0/ 0</h4>
			  </div>
			</div>
		</div>
		<div class="col-md-4">
			<div class="panel panel-default">
			  <div class="panel-heading">
			    <h3 class="panel-title">IP</h3>
			  </div>
			  <div class="panel-body">
			    <b><i>Number of rules triggered versus total rule count of the protocol</i></b>
			    <h4>0/ 0</h4>
			  </div>
			</div>
		</div>
		<div class="col-md-2"></div>
	</div>
</div>

<script src="webjars/jquery/3.4.1/jquery.min.js" type="text/javascript"></script>
<script src="webjars/bootstrap/4.3.1/js/bootstrap.min.js" type="text/javascript"></script>
</body>
</html>