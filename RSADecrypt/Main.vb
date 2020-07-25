Imports System.Security.Cryptography
Imports System.IO.Compression
Imports System.IO

Module Main

    Sub Main()
        Try
            Dim Args As String() = Environment.GetCommandLineArgs

            If Args.Count <> 2 Then
                MsgBox("Usage RSADecrypt filename")
                Exit Sub
            End If

            Dim FileToDecrypt As String = Args(1)

            If FileToDecrypt.Length > 4 Then
                If FileToDecrypt.Substring(1, 2) <> ":\" Then
                    FileToDecrypt = String.Format("{0}\{1}", Environment.CurrentDirectory, FileToDecrypt)
                End If
            Else
                FileToDecrypt = String.Format("{0}\{1}", Environment.CurrentDirectory, FileToDecrypt)
            End If

            If Not My.Computer.FileSystem.FileExists(FileToDecrypt) Then
                MsgBox("File doesn't exists", MsgBoxStyle.Critical)
                Exit Sub
            End If




            Dim AppDataDir As String = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData)
            Dim CryptoDir As String = String.Format("{0}\AgogeCryptFiles", AppDataDir)

            If Not My.Computer.FileSystem.DirectoryExists(CryptoDir) Then
                My.Computer.FileSystem.CreateDirectory(CryptoDir)
            End If

            Dim PrivateKeyFile As String = String.Format("{0}\PrivateKey.txt", CryptoDir)

            Dim RSA As New RSACryptoServiceProvider(1024)

            If My.Computer.FileSystem.FileExists(PrivateKeyFile) Then
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
                MsgBox(String.Format("Chave privada não localizada, favor copiar a mesma para o endereço{0}{0}{1}", vbCrLf, PrivateKeyFile))
                Exit Sub
            End If



            Dim destFile As String = FileToDecrypt.Substring(0, FileToDecrypt.LastIndexOf(".agg-rsa-aes"))

            Using readStream As New FileStream(FileToDecrypt, FileMode.Open)

                Dim KeyBuffer(128 - 1) As Byte
                readStream.Read(KeyBuffer, 0, 128)

                Dim DecryptedKey As Byte() = RSA.Decrypt(KeyBuffer, False)

                Dim Key(31) As Byte
                Dim IV(15) As Byte
                Buffer.BlockCopy(DecryptedKey, 0, Key, 0, 32)
                Buffer.BlockCopy(DecryptedKey, 32, IV, 0, 16)

                Dim AES As New AesCryptoServiceProvider
                AES.Key = Key
                AES.IV = IV



                Using writeStream As New FileStream(destFile, FileMode.Create)

                    'http://technet.microsoft.com/en-us/library/cc938632.aspx
                    Dim buffSize As Integer = 1024 * 64
                    Dim buff(buffSize - 1) As Byte

                    Dim P As New Progress
                    P.Show()

                    Using cryptoStream As New CryptoStream(readStream, AES.CreateDecryptor, CryptoStreamMode.Read)
                        Using inflateStream As New DeflateStream(cryptoStream, CompressionMode.Decompress)

                            Dim bytesRead As Integer

                            Do
                                bytesRead = inflateStream.Read(buff, 0, buffSize)
                                writeStream.Write(buff, 0, bytesRead)

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
