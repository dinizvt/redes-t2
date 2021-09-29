import asyncio
from grader.tcputils import *
from random import randint


class Servidor:
    def __init__(self, rede, porta):
        self.rede = rede
        self.porta = porta
        self.conexoes = {}
        self.callback = None
        self.rede.registrar_recebedor(self._rdt_rcv)

    def registrar_monitor_de_conexoes_aceitas(self, callback):
        """
        Usado pela camada de aplicação para registrar uma função para ser chamada
        sempre que uma nova conexão for aceita
        """
        self.callback = callback

    def _rdt_rcv(self, src_addr, dst_addr, segment):
        src_port, dst_port, seq_no, ack_no, \
            flags, window_size, checksum, urg_ptr = read_header(segment)

        if dst_port != self.porta:
            # Ignora segmentos que não são destinados à porta do nosso servidor
            return
        if not self.rede.ignore_checksum and calc_checksum(segment, src_addr, dst_addr) != 0:
            print('descartando segmento com checksum incorreto')
            return

        payload = segment[4*(flags>>12):]
        id_conexao = (src_addr, src_port, dst_addr, dst_port)
        (dst_addr_res, dst_port_res, src_addr_res, src_port_res) = (src_addr, src_port, dst_addr, dst_port)
        if (flags & FLAGS_SYN) == FLAGS_SYN:
            conexao = self.conexoes[id_conexao] = Conexao(self, id_conexao, seq_no+1)
            conexao.seq_no = seq_no + 1
            conexao.ack_no = seq_no + 1
            self.rede.enviar(
                fix_checksum(
                    make_header(src_port_res, dst_port_res, seq_no, seq_no+1, FLAGS_SYN | FLAGS_ACK),
                    src_addr_res,
                    dst_addr_res
                ), dst_addr_res
            )
            
            if self.callback:
                self.callback(conexao)
        elif id_conexao in self.conexoes:
            # Passa para a conexão adequada se ela já estiver estabelecida
            self.conexoes[id_conexao]._rdt_rcv(seq_no, ack_no, flags, payload)
            
        else:
            print('%s:%d -> %s:%d (pacote associado a conexão desconhecida)' %
                  (src_addr, src_port, dst_addr, dst_port))


class Conexao:
    def __init__(self, servidor, id_conexao, seq_init):
        self.seq_init = seq_init
        self.servidor = servidor
        self.id_conexao = id_conexao
        self.callback = None
        self.timer = asyncio.get_event_loop().call_later(1, self._exemplo_timer)  # um timer pode ser criado assim; esta linha é só um exemplo e pode ser removida
        #self.timer.cancel()   # é possível cancelar o timer chamando esse método; esta linha é só um exemplo e pode ser removida

    def _exemplo_timer(self):
        # Esta função é só um exemplo e pode ser removida
        print('Este é um exemplo de como fazer um timer')

    def _rdt_rcv(self, seq_no, ack_no, flags, payload):
        # TODO: trate aqui o recebimento de segmentos provenientes da camada de rede.
        print('recebido payload: %r' % payload)
        if (seq_no != self.ack_no):
            return
        if len(payload) == 0:
            return
        self.ack_no += len(payload)
        (src_addr, src_port, dst_addr, dst_port) = self.id_conexao
        self.servidor.rede.enviar(
            fix_checksum(
                make_header(dst_port, src_port, self.seq_no, self.ack_no, FLAGS_ACK),
                dst_addr,
                src_addr
            ), src_addr
        )
        self.callback(self, payload)
        # Chame self.callback(self, dados) para passar dados para a camada de aplicação após
        # garantir que eles não sejam duplicados e que tenham sido recebidos em ordem.

    # Os métodos abaixo fazem parte da API

    def registrar_recebedor(self, callback):
        """
        Usado pela camada de aplicação para registrar uma função para ser chamada
        sempre que dados forem corretamente recebidos
        """
        self.callback = callback

    def enviar(self, dados):
        """
        Usado pela camada de aplicação para enviar dados
        """
        if len(dados) <= MSS:
            (src_addr, src_port, dst_addr, dst_port) = self.id_conexao
            self.servidor.rede.enviar(
                fix_checksum(
                    make_header(src_port, dst_port, self.seq_no, self.ack_no, FLAGS_ACK) + dados,
                    src_addr,
                    dst_addr
                ), dst_addr
            )
            self.seq_no += len(dados)
        else:
            self.enviar(dados[:MSS])
            self.enviar(dados[MSS:])

    def fechar(self):
        """
        Usado pela camada de aplicação para fechar a conexão
        """
        # TODO: implemente aqui o fechamento de conexão
        pass
