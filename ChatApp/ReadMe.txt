To compile:
server compile: javac -cp "../lib/*" Server.java (from within ChatServer package)
client compile: javac -cp "../lib/*" Client.java (from within ChatClient package)

To run on localhost:
server run: java -cp "../lib/*" Server.java (from within ChatServer package)
run as Alice: java -cp "../lib/*" Client.java Alice Apass (from within ChatClient package)
run as Bob: java -cp "../lib/*" Client.java Bob Bpass (from within ChatClient package)

To run with a remote server:
server run: java -cp "../lib/*" Server.java IP_ADRRESS (from within ChatServer package)
run as Alice: java -cp "../lib/*" Client.java Alice Apass IP_ADRRESS (from within ChatClient package)
run as Bob: java -cp "../lib/*" Client.java Bob Bpass IP_ADRRESS (from within ChatClient package)

To send a text message:
Just write message on the terminal and press enter 

To send an image message: 
img|caption|image filename 
*NB: include pipes as shown above

Folder hierachry and image files: 
Within the project folder there exists a folder for both Alice and Bob. Within Alice's folder there are images Alice1.jpg
and Alice2.jpg, within Bob's folder there are images Bob1.jpg and Bob2.jpg. 
Example of an image send from Alice: 
img|hope you enjoy this image|Alice1.jpg
