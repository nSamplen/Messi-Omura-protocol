import asn1

def encodeAES(
    size,
    cipher, iv
    ):

    asn1_encoder = asn1.Encoder()

    asn1_encoder.start()

    # Sequence HEADER
    asn1_encoder.enter(asn1.Numbers.Sequence)
    asn1_encoder.enter(asn1.Numbers.Sequence)
    #Key set
    asn1_encoder.enter(asn1.Numbers.Set)
    asn1_encoder.leave()

    # Sequence_2 start
    asn1_encoder.enter(asn1.Numbers.Sequence)

    # 0x80070200 - Месси-Омуры
    asn1_encoder.write(b'\x10\x82', asn1.Numbers.OctetString)
    asn1_encoder.write(iv, asn1.Numbers.OctetString)
    asn1_encoder.write(size, asn1.Numbers.Integer)

    asn1_encoder.leave()
    #


    # Sequence HEADER end
    asn1_encoder.leave()

    asn1_encoder.write(cipher)
    asn1_encoder.leave()

    return asn1_encoder.output()


def decodeAES(data):

   
    #data = file.read()
    decoder = asn1.Decoder()
    decoder.start(data)
   # decoded_parameters = parse(decoder, decoded_parameters)
    decoder.enter()
    decoder.enter()
    decoder.enter()
    decoder.leave()

    decoder.enter()
    decoder.read() #b'\x00\x01'
    iv = decoder.read()[1]
    size = decoder.read()[1]
    decoder.leave()

   
    decoder.leave()

   
    data = decoder.read()[1]
    decoder.leave()

    with open('~tmp', 'wb') as file_cipher:
        file_cipher.write(data)#cipher_bytes)

    return  iv, size #decoded_parameters[0], decoded_parameters[1], decoded_parameters[2]


def encodeClient_p_r_ta(
    p,
    r,
    t_a
    ):

    asn1_encoder = asn1.Encoder()

    asn1_encoder.start()

    # Sequence HEADER
    asn1_encoder.enter(asn1.Numbers.Sequence)
    #Key set
    asn1_encoder.enter(asn1.Numbers.Set)

    # Sequence_2 start
    asn1_encoder.enter(asn1.Numbers.Sequence)

    # 0x80070200 - Месси-Омуры
    asn1_encoder.write(b'\x80\x07\x02\x00', asn1.Numbers.OctetString)
    asn1_encoder.write(b'mo', asn1.Numbers.UTF8String)

    asn1_encoder.enter(asn1.Numbers.Sequence)
    asn1_encoder.leave()
    #
    asn1_encoder.enter(asn1.Numbers.Sequence)
    asn1_encoder.write(p, asn1.Numbers.Integer)
    asn1_encoder.write(r, asn1.Numbers.Integer)
    asn1_encoder.leave()

    asn1_encoder.leave()

    #
    asn1_encoder.enter(asn1.Numbers.Sequence)
    asn1_encoder.write(t_a, asn1.Numbers.Integer)
    asn1_encoder.leave()

    # Sequence_2 end
    asn1_encoder.leave()

    # Set_1 end
    asn1_encoder.leave()

    #
    asn1_encoder.enter(asn1.Numbers.Sequence)
    asn1_encoder.leave()


    # Sequence HEADER end
   # asn1_encoder.leave()

    return asn1_encoder.output()


def encodeServer_tab(
    t_ab
    ):

    asn1_encoder = asn1.Encoder()

    asn1_encoder.start()

    # Sequence HEADER
    asn1_encoder.enter(asn1.Numbers.Sequence)
    #Key set
    asn1_encoder.enter(asn1.Numbers.Set)

    # Sequence_2 start
    asn1_encoder.enter(asn1.Numbers.Sequence)

    # 0x80070200 - Месси-Омуры
    asn1_encoder.write(b'\x80\x07\x02\x00', asn1.Numbers.OctetString)
    asn1_encoder.write(b'mo', asn1.Numbers.UTF8String)

    asn1_encoder.enter(asn1.Numbers.Sequence)
    asn1_encoder.leave()
    #
    asn1_encoder.enter(asn1.Numbers.Sequence)
    asn1_encoder.leave()

    #
    asn1_encoder.enter(asn1.Numbers.Sequence)
    asn1_encoder.write(t_ab, asn1.Numbers.Integer)
    asn1_encoder.leave()

    # Sequence_2 end
    asn1_encoder.leave()

    # Set_1 end
    asn1_encoder.leave()

    #
    asn1_encoder.enter(asn1.Numbers.Sequence)
    asn1_encoder.leave()


    # Sequence HEADER end
    asn1_encoder.leave()

    return asn1_encoder.output()

def encodeClient_tb(
    t_b,
    len
    ):

    asn1_encoder = asn1.Encoder()

    asn1_encoder.start()

    # Sequence HEADER
    asn1_encoder.enter(asn1.Numbers.Sequence)
    #Key set
    asn1_encoder.enter(asn1.Numbers.Set)

    # Sequence_2 start
    asn1_encoder.enter(asn1.Numbers.Sequence)

    # 0x80070200 - Месси-Омуры
    asn1_encoder.write(b'\x80\x07\x02\x00', asn1.Numbers.OctetString)
    asn1_encoder.write(b'mo', asn1.Numbers.UTF8String)

    asn1_encoder.enter(asn1.Numbers.Sequence)
    asn1_encoder.leave()
    #
    asn1_encoder.enter(asn1.Numbers.Sequence)
    asn1_encoder.leave()

    #
    asn1_encoder.enter(asn1.Numbers.Sequence)
    asn1_encoder.write(t_b, asn1.Numbers.Integer)
    asn1_encoder.leave()

    # Sequence_2 end
    asn1_encoder.leave()

    # Set_1 end
    asn1_encoder.leave()

    #
    asn1_encoder.enter(asn1.Numbers.Sequence)
    asn1_encoder.write(b'\x10\x82', asn1.Numbers.OctetString)
    asn1_encoder.write(len, asn1.Numbers.Integer)
    asn1_encoder.leave()


    # Sequence HEADER end
    asn1_encoder.leave()

    return asn1_encoder.output()

def parse(file, decoded_values):

    while not file.eof():
        try:
            tag = file.peek()

            if tag.nr == asn1.Numbers.Null:
                break

            if tag.typ == asn1.Types.Primitive:
                tag, value = file.read()

                if tag.nr == asn1.Numbers.Integer:
                    decoded_values.append(value)

            else:
                file.enter()
                decoded_values = parse(file, decoded_values)
                file.leave()

        except asn1.Error:
            break

    return decoded_values

def decodeServer_p_r_ta(data):

    #data = file.read()
    decoder = asn1.Decoder()
    decoder.start(data)
   # decoded_parameters = parse(decoder, decoded_parameters)
    
    decoder.enter() #-sequence header
    decoder.enter() #set
    decoder.enter() #sequence key

    decoder.read() # идентификатор алгоритма (протокол Месси–Омуры) 80 07 02 00
    decoder.read() # может не задействоваться или использоваться для идентификации будущего переданного сообщения

    decoder.enter()
    decoder.leave()

    decoder.enter()
    p = decoder.read()[1]
    r = decoder.read()[1]
    decoder.leave()

    decoder.leave()

    decoder.enter()
    t_a = decoder.read()[1]
    decoder.leave()

    decoder.leave()
    decoder.leave()

    decoder.enter()
  
    decoder.leave()  

    return p, r, t_a #decoded_parameters[0], decoded_parameters[1], decoded_parameters[2]

def decodeClient_tab(data):

    decoder = asn1.Decoder()
    decoder.start(data)
    
    decoder.enter() #-sequence header
    decoder.enter() #set
    decoder.enter() #sequence key

    decoder.read() # идентификатор алгоритма (протокол Месси–Омуры) 80 07 02 00
    decoder.read() # может не задействоваться или использоваться для идентификации будущего переданного сообщения

    decoder.enter()
    decoder.leave()

    decoder.enter()
    decoder.leave()

    decoder.enter()
    t_ab = decoder.read()[1]
    decoder.leave()

    decoder.leave()
    decoder.leave()

    decoder.enter()
    decoder.leave()  

    decoder.leave()  

    return t_ab #decoded_parameters[0], decoded_parameters[1], decoded_parameters[2]

def decodeServer_tb(data):

    decoder = asn1.Decoder()
    decoder.start(data)
    
    decoder.enter() #-sequence header
    decoder.enter() #set
    decoder.enter() #sequence key

    decoder.read() # идентификатор алгоритма (протокол Месси–Омуры) 80 07 02 00
    decoder.read() # может не задействоваться или использоваться для идентификации будущего переданного сообщения

    decoder.enter()
    decoder.leave()

    decoder.enter()
    decoder.leave()

    decoder.enter()
    t_b = decoder.read()[1]
    decoder.leave()

    decoder.leave()
    decoder.leave()

    decoder.enter()
    decoder.read()
    len = decoder.read()[1]
    decoder.leave()  

    decoder.leave()  

    return t_b, len #decoded_parameters[0], decoded_parameters[1], decoded_parameters[2]


