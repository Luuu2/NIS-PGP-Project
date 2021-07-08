# NIS-PGP-Project
Pretty Good Privacy cryptosystem that combines shared key encryption, public-key encryption and certificates.
This is an honors project for our Network and Internetwork security course.

Our chat application has a client-server architecture and follows pretty good privacy security protocols.We have two clients and one server, look through our internal readme document to run our code and test it. We have implemented connections between server and clients from different locations, however firewalls can get in the way. Two devices under the same network work well.

The sending and receiving applications have:

  *A private and public key pair of their own
  
  *The public key of the Certification Authority
  
  *A certificate (containing the client’s own public key) signed by the Certification Authority

The sending and receiving applications do the following:

  *Setup a connection for communication
  
  *Exchange certificates
  
  *Load / encode image files and read in captions
  
  *Save decoded strings as a file and display captions
  
  *Encrypt, compress, hash messages (and the reverse)
  
  *Exchange encrypted messages
