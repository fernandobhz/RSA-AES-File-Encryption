Imports System.Security.Cryptography
Imports System.IO.Compression
Imports System.IO

Module Main

    Sub Main()
        Try

        
            Dim Args As String() = Environment.GetCommandLineArgs

            If Args.Count <> 2 Then
                MsgBox("Usage RSAEncrypt filename")
                Exit Sub
            End If

            Dim FileToEncrypt As String = Args(1)

            If FileToEncrypt.Length > 4 Then
                If FileToEncrypt.Substring(1, 2) <> ":\" Then
                    FileToEncrypt = String.Format("{0}\{1}", Environment.CurrentDirectory, FileToEncrypt)
                End If
            Else
                FileToEncrypt = String.Format("{0}\{1}", Environment.CurrentDirectory, FileToEncrypt)
            End If

            If Not My.Computer.FileSystem.FileExists(FileToEncrypt) Then
                MsgBox("File doesn't exists ", MsgBoxStyle.Critical)
                Exit Sub
            End If



            Dim AppDataDir As String = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData)
            Dim CryptoDir As String = String.Format("{0}\AgogeCryptFiles", AppDataDir)

            If Not My.Computer.FileSystem.DirectoryExists(CryptoDir) Then
                My.Computer.FileSystem.CreateDirectory(CryptoDir)
            End If

            Dim PrivateKeyFile As String = String.Format("{0}\PrivateKey.txt", CryptoDir)
            Dim PublicKeyFile As String = String.Format("{0}\PublicKey.txt", CryptoDir)

            Dim RSA As New RSACryptoServiceProvider(1024)

            If My.Computer.FileSystem.FileExists(PublicKeyFile) Then
                Dim FContent As String = My.Computer.FileSystem.ReadAllText(PublicKeyFile)
                Dim FBuffer As Byte() = Convert.FromBase64String(FContent)
                Dim FXml As String = System.Text.Encoding.UTF8.GetString(FBuffer)

                RSA.FromXmlString(FXml)
            ElseIf My.Computer.FileSystem.FileExists(PrivateKeyFile) Then
                MsgBox("Somente encontramos sua chave privada, sua senha é necessária")

                Dim Pwd As String = String.Empty

                Do
                    Pwd = InputBox("Digite a senha da chave privada", "Senha chave privada")
                Loop While String.IsNullOrEmpty(Pwd)

                Dim FContent As String = My.Computer.FileSystem.ReadAllText(PrivateKeyFile)
                Dim FBuffer As Byte() = Convert.FromBase64String(FContent)
                Dim FDecryped As Byte() = DecryptSmallAes256(Pwd, FBuffer)
                Dim FXml As String = System.Text.Encoding.UTF8.GetString(FDecryped)

                RSA.FromXmlString(FXml)
            Else
                MsgBox(String.Format("Você não possue um par de chaves publica/privada para criptografia, vamos gerar uma agora, as chaves serão gravadas no seguinte endereço{0}{0}{1}{0}{2}", vbCrLf, PublicKeyFile, PrivateKeyFile))

                Dim Pwd As String = String.Empty

                Do
                    Pwd = InputBox("Digite uma senha para proteger sua chave privada", "Senha chave privada")
                Loop While String.IsNullOrEmpty(Pwd)


                Dim PrivateKeyContent As String = RSA.ToXmlString(True)
                Dim PrivateKeyBuffer As Byte() = System.Text.Encoding.UTF8.GetBytes(PrivateKeyContent)
                Dim PrivateKeyEncrypted As Byte() = EncryptSmallDataWithAes256(Pwd, PrivateKeyBuffer)
                Dim PrivateKeyBase64 As String = Convert.ToBase64String(PrivateKeyEncrypted)


                Dim PublicKeyContent As String = RSA.ToXmlString(False)
                Dim PublicKeyBuffer As Byte() = System.Text.Encoding.UTF8.GetBytes(PublicKeyContent)
                Dim PublicKeyBase64 As String = Convert.ToBase64String(PublicKeyBuffer)


                My.Computer.FileSystem.WriteAllText(PrivateKeyFile, PrivateKeyBase64, False)
                My.Computer.FileSystem.WriteAllText(PublicKeyFile, PublicKeyBase64, False)

                MsgBox(String.Format("Guarde as chaves em local seguro, não será possível recuperar os arquivos caso você perca as chaves e a senha{0}{0}Vou abrir os arquivos no bloco de notas, para que você possa fazer uma cópia dos mesmos", vbCrLf))

                Process.Start(PrivateKeyFile)
                Process.Start(PublicKeyFile)
            End If



            Dim AES As New AesCryptoServiceProvider

            Dim KeyBuffer(32 + 16 - 1) As Byte
            Buffer.BlockCopy(AES.Key, 0, KeyBuffer, 0, AES.Key.Length)
            Buffer.BlockCopy(AES.IV, 0, KeyBuffer, AES.Key.Length, AES.IV.Length)

            Dim EncryptedKey As Byte() = RSA.Encrypt(KeyBuffer, False)



            Dim destFile As String = String.Format("{0}.agg-rsa-aes", FileToEncrypt)

            Using readStream As New FileStream(FileToEncrypt, FileMode.Open)

                Using writeStream As New FileStream(destFile, FileMode.Create)

                    writeStream.Write(EncryptedKey, 0, EncryptedKey.Length)

                    'http://technet.microsoft.com/en-us/library/cc938632.aspx
                    Dim buffSize As Integer = 1024 * 64
                    Dim buff(buffSize - 1) As Byte

                    Dim P As New Progress
                    P.Show()

                    Using cryptoStream As New CryptoStream(writeStream, AES.CreateEncryptor, CryptoStreamMode.Write)
                        Using deflateStream As New DeflateStream(cryptoStream, CompressionLevel.Fastest)

                            Dim bytesRead As Integer

                            Do
                                bytesRead = readStream.Read(buff, 0, buffSize)
                                deflateStream.Write(buff, 0, bytesRead)

                                P.ProgressBar1.Value = readStream.Position / readStream.Length * 100
                                Application.DoEvents()
                            Loop Until bytesRead = 0

                        End Using
                    End Using

                End Using

            End Using
        Catch ex As Exception
            MsgBox(String.Format("Error: {1}{0}Stack Trace:{0} {2}", vbCrLf, ex.Message, ex.StackTrace))
        End Try
    End Sub
End Module


Public Module AesSmallCrypt

    Private Function BuildPasswd(Passwd As String) As Byte()
        Dim DefaultPassword = "MOV EABX MOV EEX NULL CALL EBX STD CALL"

        Dim Passwd256Bits As String = String.Concat(Passwd, DefaultPassword).Substring(0, 32)

        Return System.Text.Encoding.ASCII.GetBytes(Passwd256Bits)

    End Function

    Private Function BuildIV(Passwd As String) As Byte()
        Dim DefaultPassword = "NULL CALL EBX STD CALL MOV EABX MOV EEX"

        Dim IV128Bits As String = String.Concat(Passwd, DefaultPassword).Substring(0, 16)

        Return System.Text.Encoding.ASCII.GetBytes(IV128Bits)

    End Function



    Public Function EncryptSmallDataWithAes256(Passwd As String, Data As Byte()) As Byte()

        Dim AES As New AesCryptoServiceProvider
        AES.Key = BuildPasswd(Passwd)
        AES.IV = BuildIV(Passwd)

        Dim MS As New MemoryStream

        Using cStream As New CryptoStream(MS, AES.CreateEncryptor, CryptoStreamMode.Write)
            cStream.Write(Data, 0, Data.Length)
        End Using

        Return MS.ToArray

    End Function

    Public Function DecryptSmallAes256(Passwd As String, Data As Byte()) As Byte()

        Dim AES As New AesCryptoServiceProvider
        AES.Key = BuildPasswd(Passwd)
        AES.IV = BuildIV(Passwd)

        Dim MS As New MemoryStream(Data)

        Dim Result As New MemoryStream
        Using dStream As New CryptoStream(MS, AES.CreateDecryptor, CryptoStreamMode.Read)
            dStream.CopyTo(Result)
        End Using

        Return Result.ToArray

    End Function

End Module
