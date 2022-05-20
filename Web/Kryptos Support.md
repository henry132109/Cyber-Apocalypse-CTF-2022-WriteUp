Usually when we can supply things for admin to "review", think about *XSS*. As the first (i.e. "easiest") box, simple *cookie stealing* will do.

![image](https://user-images.githubusercontent.com/26480299/169432977-26641f16-fcc8-41a2-8ddb-aa896bde1bfc.png)
![image](https://user-images.githubusercontent.com/26480299/169433173-7322ab56-15d4-4e38-8700-755e8044ca54.png)

In practice cookies are almost always set to http-only and this will not work.

We can visit the backend login page, from which we learn about `/tickets`, which we can access now, and then `/settings`.

What we enter for the new password is not important. Check the payload:

![image](https://user-images.githubusercontent.com/26480299/169434129-645e732d-9bd6-48e9-8a3d-d3241abfca65.png)

The uid (i.e. user id) is supplied to the request. **Now we can change the uid to 1**, as admins are often the first users in systems with sequential IDs. This error in business logic is called *Insecure direct object references (IDORs)*.

Pre-CTF guide: Browsers nowadays almost always provide an option to send fetch requests:

![image](https://user-images.githubusercontent.com/26480299/169434732-a3c894a5-a8be-4b9e-86a6-d4a2cdf9a9ab.png)

![image](https://user-images.githubusercontent.com/26480299/169434289-f6b4a35b-aeca-4978-8e10-cbcd03783b2f.png)

The server gives us the username and we don't even need to guess.

![image](https://user-images.githubusercontent.com/26480299/169434383-2925f43a-3dcb-4eef-bcb8-e72d52f0f815.png)

**Flag: HTB{x55_4nd_id0rs_ar3_fun!!}**
