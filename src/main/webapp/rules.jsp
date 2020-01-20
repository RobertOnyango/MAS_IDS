<%@ page language="java" contentType="text/html; charset=ISO-8859-1"
    pageEncoding="ISO-8859-1" isELIgnored="false"%>
<%@taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<!DOCTYPE html>
<html>
<head>
<meta charset="ISO-8859-1">
<link href="webjars/bootstrap/4.3.1/css/bootstrap.min.css" rel="stylesheet">
<title>MAS_IDS SNORT Rules</title>
</head>
<body>

<nav class="navbar navbar-expand-lg navbar-light bg-light">
  <a class="navbar-brand" href="#">MAS_IDS</a>
  <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNav" aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
    <span class="navbar-toggler-icon"></span>
  </button>
  <div class="collapse navbar-collapse" id="navbarNav">
    <ul class="navbar-nav">
      <li class="nav-item">
        <a class="nav-link" href="home">Home</a>
      </li>
      <li class="nav-item active">
        <a class="nav-link" href="rules">Rules <span class="sr-only">(current)</span> </a>
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

<h2 class="text-center">SNORT Rules</h2>
<div class="container">
	<div class="row">
		<div class="col-md-3"> <h5>Total number of rules currently used in system:<i> ${rule} </i></h5> </div>
		<div class="col-md-3"></div>
		<div class="col-md-3"></div>
		<div class="col-md-3">
			<h6>
				Download updated rules from SNORT <i>(link below)</i>: <br>
				<a href="https://www.snort.org"><i>snort.org</i></a>
			</h6>
		</div>
	</div>
</div>
<br>
<div class="container">
	<div class="row">
		<div class="col-md-3"> TCP Rules: 1</div>
		<div class="col-md-3"> UDP Rules: 0 </div>
		<div class="col-md-3"> ICMP Rules: 0</div>
		<div class="col-md-3"> IP Rules: 0 </div>
	</div>
</div>
<br>
<div class="container">
	<div class="row">
		<div class="col-md-2"></div>
		<div class="col-md-8">
			<div class="panel panel-default">
			  <div class="panel-heading">
			    <h3 class="panel-title">Snort Rules</h3>
			  </div>
			  <div class="panel-body" style="max-height: 100; overflow-y: scroll;">
			    	${rule1} <br><br>
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