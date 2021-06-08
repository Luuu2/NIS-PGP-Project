# NIS-PGP-Project
Pretty Good Privacy cryptosystem that combines shared key encryption, public-key encryption and certificates.
This is an honors project for our Network and Internetwork security course.

Our task
Create two Client applications named “Alice” and “Bob” that initially exchange and validate each
other’s public keys issued by a Certification Authority that they both trust. Thereafter, messages
should be transmitted to each other, using the shared key, private key, public key, hashing and
compression functions, in the same manner as PGP.
In a communication session, the sender should be able to load an image and encode it into a string
format that will serve as part of the message. In addition, a text caption of the image will serve as the
other part of the message. Thus, the message prior to applying any cryptographic algorithms should
contain a caption of the image and the encoded image. The emphasis is on image transmission;
sending only encrypted captions will not earn full marks. See Section 3 for rubric.
To send a message, a Client communication system (based on UDP or TCP) should be established. In
a one-way communication session, the two clients can be separated as a sender and a receiver.
Enabling Clients to participate in a continuous chat (act as both sender and receiver), i.e., a two-way
communication session, earns full marks. See Section 3 for rubric. Communication sessions are
initiated in various manners (typically the receiver should listen while the sender initiates
communication). Moreover, a Client application may represent a class or separate instance of the
system running, as long as there are two entities that may communicate.
It is important to note that the trusted third-party interaction (obtaining certificates from the
Certification Authority) does not have to exist as a third Client in your final submission. However,
certificates must be generated and exchanged for public-key authentication.
The sending and receiving applications are expected to have:
  A private and public key pair of their own
  The public key of the Certification Authority
  A certificate (containing the client’s own public key) signed by the Certification Authority
The sending and receiving applications are expected to:
  Setup a connection for communication
  Exchange certificates
  Load / encode image files and read in captions
  Save decoded strings as a file and display captions
  Encrypt, compress, hash messages (and the reverse)
  Exchange encrypted messages
