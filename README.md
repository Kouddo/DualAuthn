**authentication**

An authentication framework which makes use of hardware-based key managers to make authentication more secure than a purely JWT-based approach. 

It still uses JWTs, but with an extremely short lifespan, so that the authentication scheme is more resilient to token hijacking attacks. 

F authentication this scheme instead creates a public-private key pair on the user's device. The public key is sent to the host and associated with that user. The user signs a challenge sent by the host using their private key whenever they want to be authenticated, thus ensuring that they're actually the ones making the request. Upon validation of the signature by the server, a JWT is sent so that user activity over a short period of time is authenticated, so that the signature scheme doesn't have to take place every time a user performs an action balancing performance with security.

