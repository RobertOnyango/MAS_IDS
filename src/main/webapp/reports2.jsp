<%@ page language="java" contentType="text/html; charset=ISO-8859-1"
    pageEncoding="ISO-8859-1"%>
<!DOCTYPE html>
<html>
<head>
<meta charset="ISO-8859-1">
<link href="webjars/bootstrap/4.3.1/css/bootstrap.min.css" rel="stylesheet">
<title>MAS_IDS Reports</title>
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
        <a class="nav-link" href="home">Home <span class="sr-only">(current)</span></a>
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

<h2 class="text-center">Intrusion Detection Report</h2>

<div class="container">
<table class="table">
	<thead>
		<tr>
			<th>Protocol</th>
			<th>Source IP</th>
			<th>Destination IP</th>
			<th>Message</th>
			<th>ClassType</th>
		</tr>
	</thead>
	<tbody>
		<tr>
			<td>tcp</td>
			<td>32.241.23.245</td>
			<td>10.58.101.36</td>
			<td>MALWARE-BACKDOOR Doly 2.0 access</td>
			<td>misc-activity</td>
		</tr>
		
	</tbody>
</table>
</div>

<script src="webjars/jquery/3.4.1/jquery.min.js" type="text/javascript"></script>
<script src="webjars/bootstrap/4.3.1/js/bootstrap.min.js" type="text/javascript"></script>
</body>
</html>