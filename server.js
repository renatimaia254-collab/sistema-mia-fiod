const express = require('express');
const cors = require('cors');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const fs = require('fs');
const sqlite3 = require('sqlite3').verbose();

const app = express();
const PORT = process.env.PORT || 10000;

app.use(session({
  secret: 'mia-fiod-secret-key-2026',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 24 * 60 * 60 * 1000 }
}));

app.use(cors());
app.use(express.json());
app.use(express.static('public'));

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = '/tmp/uploads';
    if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    cb(null, `${Date.now()}-${file.originalname}`);
  }
});
const upload = multer({ storage });

const DB_PATH = process.env.DISK_PATH || '/data/atendimentos.db';
const db = new sqlite3.Database(DB_PATH);

console.log(`📁 Banco de dados: ${DB_PATH}`);

db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS usuarios (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE NOT NULL,
      senha TEXT NOT NULL,
      nome TEXT NOT NULL,
      whatsapp TEXT,
      tipo TEXT DEFAULT 'usuario',
      status TEXT DEFAULT 'ativo',
      data_cadastro TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);

  db.run(`ALTER TABLE usuarios ADD COLUMN whatsapp TEXT`, (err) => {
    if (err && !err.message.includes('duplicate column name')) {}
  });

  db.run(`
    CREATE TABLE IF NOT EXISTS listas (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      nome_arquivo TEXT,
      ddd TEXT,
      banco TEXT DEFAULT 'pagbank',
      quantidade_total INTEGER,
      quantidade_disponivel INTEGER,
      conteudo TEXT,
      data_upload TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS solicitacoes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      usuario_id INTEGER,
      lista_id INTEGER,
      quantidade INTEGER,
      status TEXT DEFAULT 'pendente',
      data_solicitacao TEXT DEFAULT CURRENT_TIMESTAMP,
      data_autorizacao TEXT
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS minhas_listas (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      usuario_id INTEGER,
      lista_id INTEGER,
      banco TEXT DEFAULT 'pagbank',
      conteudo TEXT,
      data_obtencao TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS fichas (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      nomeCliente TEXT,
      telefoneCliente TEXT,
      assunto TEXT,
      nomeGerente TEXT,
      horarioAgendado TEXT,
      vulgo TEXT,
      zap TEXT,
      status TEXT,
      horarioChegada TEXT,
      observacao TEXT,
      atendidoPor TEXT,
      dataEncerramento TEXT,
      comentario TEXT DEFAULT '',
      banco TEXT DEFAULT 'pagbank'
    )
  `);

  db.get(`SELECT * FROM usuarios WHERE email = 'admin@miafiod.com'`, (err, row) => {
    if (!row) {
      const hash = bcrypt.hashSync('admin123', 10);
      db.run(`INSERT INTO usuarios (email, senha, nome, whatsapp, tipo, status) VALUES (?, ?, ?, ?, 'admin', 'ativo')`, 
        ['admin@miafiod.com', hash, 'Administrador MIA FIOD', '11999999999']);
      console.log('✅ Usuário admin criado: admin@miafiod.com / admin123');
    }
  });
});

function verificarLogin(req, res, next) {
  if (!req.session.usuarioId) {
    return res.status(401).json({ erro: 'Não autorizado.' });
  }
  next();
}

function verificarAdmin(req, res, next) {
  if (!req.session.usuarioId || req.session.usuarioTipo !== 'admin') {
    return res.status(403).json({ erro: 'Acesso negado.' });
  }
  next();
}

// ========== AUTENTICAÇÃO ==========

app.post('/api/cadastrar', async (req, res) => {
  const { email, senha, nome, whatsapp } = req.body;
  if (!email || !senha || !nome) {
    return res.status(400).json({ erro: 'Preencha todos os campos' });
  }
  const senhaHash = bcrypt.hashSync(senha, 10);
  db.run(`INSERT INTO usuarios (email, senha, nome, whatsapp) VALUES (?, ?, ?, ?)`, 
    [email, senhaHash, nome, whatsapp || ''], 
    function(err) {
      if (err) {
        if (err.message.includes('UNIQUE')) {
          return res.status(400).json({ erro: 'E-mail já cadastrado' });
        }
        return res.status(500).json({ erro: err.message });
      }
      res.json({ success: true });
    });
});

app.post('/api/login', (req, res) => {
  const { email, senha } = req.body;
  db.get(`SELECT * FROM usuarios WHERE email = ?`, [email], (err, usuario) => {
    if (err) return res.status(500).json({ erro: err.message });
    if (!usuario) return res.status(401).json({ erro: 'E-mail ou senha incorretos' });
    if (usuario.status !== 'ativo') return res.status(401).json({ erro: 'Usuário bloqueado' });
    
    const senhaValida = bcrypt.compareSync(senha, usuario.senha);
    if (!senhaValida) return res.status(401).json({ erro: 'E-mail ou senha incorretos' });
    
    req.session.usuarioId = usuario.id;
    req.session.usuarioEmail = usuario.email;
    req.session.usuarioNome = usuario.nome;
    req.session.usuarioWhatsapp = usuario.whatsapp || '';
    req.session.usuarioTipo = usuario.tipo;
    
    res.json({ success: true, tipo: usuario.tipo, nome: usuario.nome });
  });
});

app.post('/api/logout', (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

app.get('/api/verificar-sessao', (req, res) => {
  if (req.session.usuarioId) {
    res.json({ 
      logado: true, 
      tipo: req.session.usuarioTipo,
      nome: req.session.usuarioNome,
      email: req.session.usuarioEmail,
      whatsapp: req.session.usuarioWhatsapp
    });
  } else {
    res.json({ logado: false });
  }
});

app.get('/api/usuario/dados', verificarLogin, (req, res) => {
  res.json({
    nome: req.session.usuarioNome,
    email: req.session.usuarioEmail,
    whatsapp: req.session.usuarioWhatsapp || ''
  });
});

// ========== ADMIN USUÁRIOS ==========

app.get('/api/admin/usuarios', verificarAdmin, (req, res) => {
  db.all(`SELECT id, email, nome, whatsapp, tipo, status, data_cadastro FROM usuarios`, (err, usuarios) => {
    if (err) return res.status(500).json({ erro: err.message });
    res.json(usuarios);
  });
});

app.put('/api/admin/usuarios/:id/status', verificarAdmin, (req, res) => {
  const { status } = req.body;
  db.run(`UPDATE usuarios SET status = ? WHERE id = ?`, [status, req.params.id], function(err) {
    if (err) return res.status(500).json({ erro: err.message });
    res.json({ success: true });
  });
});

app.put('/api/admin/usuarios/:id/reset-senha', verificarAdmin, (req, res) => {
  const novaSenhaHash = bcrypt.hashSync('123456', 10);
  db.run(`UPDATE usuarios SET senha = ? WHERE id = ?`, [novaSenhaHash, req.params.id], function(err) {
    if (err) return res.status(500).json({ erro: err.message });
    res.json({ success: true, novaSenha: '123456' });
  });
});

app.delete('/api/admin/usuarios/:id', verificarAdmin, (req, res) => {
  db.run(`DELETE FROM usuarios WHERE id = ? AND tipo != 'admin'`, [req.params.id], function(err) {
    if (err) return res.status(500).json({ erro: err.message });
    res.json({ success: true });
  });
});

// ========== LISTAS (COM NOVO FORMATO) ==========

// Função para processar o novo formato de lista
function processarNovoFormatoLista(conteudo, ddd, banco) {
  const linhas = conteudo.split('\n');
  const fichas = [];
  let fichaAtual = '';
  let dentroFicha = false;
  
  for (let i = 0; i < linhas.length; i++) {
    const linha = linhas[i].trim();
    
    // Detecta início de nova ficha (começa com número seguido de ponto ou hífen)
    if (linha.match(/^\d+\.\s+[A-Za-z]/) || linha.match(/^\d+-\s+[A-Za-z]/)) {
      if (fichaAtual) {
        fichas.push(fichaAtual);
      }
      fichaAtual = linha;
      dentroFicha = true;
    } 
    else if (dentroFicha && linha.startsWith('- ')) {
      fichaAtual += '\n' + linha;
    }
    else if (dentroFicha && linha === '---') {
      if (fichaAtual) {
        fichas.push(fichaAtual);
      }
      fichaAtual = '';
      dentroFicha = false;
    }
    else if (dentroFicha && linha !== '') {
      fichaAtual += '\n' + linha;
    }
  }
  if (fichaAtual && fichaAtual.trim()) {
    fichas.push(fichaAtual);
  }
  
  const conteudoUnificado = fichas.join('\n\n---\n\n');
  return { fichas, conteudoUnificado };
}

app.post('/api/admin/importar-lista', verificarAdmin, upload.single('arquivo'), (req, res) => {
  if (!req.file) return res.status(400).json({ erro: 'Envie um arquivo TXT' });
  
  const ddd = req.query.ddd || '00';
  const banco = req.query.banco || 'pagbank';
  const conteudo = fs.readFileSync(req.file.path, 'utf8');
  const { fichas, conteudoUnificado } = processarNovoFormatoLista(conteudo, ddd, banco);
  
  if (fichas.length === 0) {
    return res.status(400).json({ erro: 'Nenhuma ficha encontrada no formato correto.' });
  }
  
  db.get(`SELECT id, quantidade_disponivel, conteudo FROM listas WHERE ddd = ? AND banco = ?`, [ddd, banco], (err, listaExistente) => {
    if (err) return res.status(500).json({ erro: err.message });
    
    if (listaExistente) {
      const novoConteudo = listaExistente.conteudo + '\n\n---\n\n' + conteudoUnificado;
      const novaQuantidade = listaExistente.quantidade_disponivel + fichas.length;
      db.run(`UPDATE listas SET quantidade_disponivel = ?, conteudo = ? WHERE ddd = ? AND banco = ?`, 
        [novaQuantidade, novoConteudo, ddd, banco], (err2) => {
        if (err2) return res.status(500).json({ erro: err2.message });
        res.json({ success: true, total: fichas.length, mensagem: `${fichas.length} fichas adicionadas ao ${banco.toUpperCase()} DDD ${ddd}` });
      });
    } else {
      db.run(`INSERT INTO listas (nome_arquivo, ddd, banco, quantidade_total, quantidade_disponivel, conteudo) VALUES (?, ?, ?, ?, ?, ?)`,
        [req.file.originalname, ddd, banco, fichas.length, fichas.length, conteudoUnificado], function(err2) {
        if (err2) return res.status(500).json({ erro: err2.message });
        res.json({ success: true, total: fichas.length, mensagem: `${fichas.length} fichas importadas para ${banco.toUpperCase()} DDD ${ddd}` });
      });
    }
  });
  
  fs.unlinkSync(req.file.path);
});

app.get('/api/listas-disponiveis', verificarLogin, (req, res) => {
  db.all(`SELECT id, ddd, banco, quantidade_disponivel as quantidade FROM listas WHERE quantidade_disponivel > 0 ORDER BY banco, ddd`, (err, listas) => {
    if (err) return res.status(500).json({ erro: err.message });
    res.json(listas);
  });
});

app.post('/api/solicitar-lista', verificarLogin, (req, res) => {
  const { lista_id, quantidade } = req.body;
  const usuario_id = req.session.usuarioId;
  
  if (!usuario_id) {
    return res.status(401).json({ erro: 'Usuário não logado' });
  }
  
  if (quantidade > 50) {
    return res.status(400).json({ erro: 'Limite máximo de 50 fichas por solicitação.' });
  }
  
  if (quantidade < 1) {
    return res.status(400).json({ erro: 'Quantidade inválida.' });
  }
  
  db.get(`SELECT * FROM listas WHERE id = ? AND quantidade_disponivel >= ?`, [lista_id, quantidade], (err, lista) => {
    if (err) return res.status(500).json({ erro: err.message });
    if (!lista) return res.status(400).json({ erro: 'Quantidade indisponível' });
    
    db.run(`INSERT INTO solicitacoes (usuario_id, lista_id, quantidade, status) VALUES (?, ?, ?, 'pendente')`,
      [usuario_id, lista_id, quantidade], function(err2) {
      if (err2) return res.status(500).json({ erro: err2.message });
      res.json({ success: true, mensagem: 'Solicitação enviada!' });
    });
  });
});

app.get('/api/minhas-solicitacoes', verificarLogin, (req, res) => {
  db.all(`
    SELECT s.*, l.ddd, l.banco FROM solicitacoes s 
    JOIN listas l ON s.lista_id = l.id 
    WHERE s.usuario_id = ? ORDER BY s.data_solicitacao DESC`, [req.session.usuarioId], (err, rows) => {
    if (err) return res.status(500).json({ erro: err.message });
    res.json(rows);
  });
});

app.get('/api/minhas-listas', verificarLogin, (req, res) => {
  db.all(`
    SELECT ml.*, l.ddd, l.banco FROM minhas_listas ml 
    JOIN listas l ON ml.lista_id = l.id 
    WHERE ml.usuario_id = ? ORDER BY ml.data_obtencao DESC`, [req.session.usuarioId], (err, rows) => {
    if (err) return res.status(500).json({ erro: err.message });
    res.json(rows);
  });
});

app.get('/api/download-lista/:id', verificarLogin, (req, res) => {
  db.get(`SELECT * FROM minhas_listas WHERE id = ? AND usuario_id = ?`, 
    [req.params.id, req.session.usuarioId], (err, lista) => {
    if (err) return res.status(500).json({ erro: err.message });
    if (!lista) return res.status(404).json({ erro: 'Lista não encontrada' });
    
    const conteudo = lista.conteudo || '';
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename=lista_${lista.id}.txt`);
    res.send(conteudo);
  });
});

app.get('/api/admin/solicitacoes-pendentes', verificarAdmin, (req, res) => {
  db.all(`
    SELECT s.*, u.nome as usuario_nome, u.email, l.ddd, l.banco
    FROM solicitacoes s
    JOIN usuarios u ON s.usuario_id = u.id
    JOIN listas l ON s.lista_id = l.id
    WHERE s.status = 'pendente'
    ORDER BY s.data_solicitacao ASC
  `, (err, rows) => {
    if (err) return res.status(500).json({ erro: err.message });
    res.json(rows);
  });
});

app.put('/api/admin/autorizar-solicitacao/:id', verificarAdmin, (req, res) => {
  const { acao } = req.body;
  
  db.get(`SELECT * FROM solicitacoes WHERE id = ?`, [req.params.id], (err, solicitacao) => {
    if (err) return res.status(500).json({ erro: err.message });
    if (!solicitacao) return res.status(404).json({ erro: 'Solicitação não encontrada' });
    
    if (acao === 'aprovar') {
      db.get(`SELECT * FROM listas WHERE id = ?`, [solicitacao.lista_id], (err2, lista) => {
        if (err2) return res.status(500).json({ erro: err2.message });
        
        if (lista.quantidade_disponivel < solicitacao.quantidade) {
          return res.status(400).json({ erro: 'Quantidade insuficiente' });
        }
        
        const quantidadeReal = Math.min(solicitacao.quantidade, lista.quantidade_disponivel);
        
        const fichasSeparadas = lista.conteudo.split('\n\n---\n\n');
        const fichasEntregues = fichasSeparadas.slice(0, quantidadeReal);
        const conteudoEntregue = fichasEntregues.join('\n\n---\n\n');
        
        db.run(`INSERT INTO minhas_listas (usuario_id, lista_id, banco, conteudo) VALUES (?, ?, ?, ?)`,
          [solicitacao.usuario_id, solicitacao.lista_id, lista.banco, conteudoEntregue]);
        
        const novaQuantidade = lista.quantidade_disponivel - quantidadeReal;
        const novoConteudo = fichasSeparadas.slice(quantidadeReal).join('\n\n---\n\n');
        
        db.run(`UPDATE listas SET quantidade_disponivel = ?, conteudo = ? WHERE id = ?`, 
          [novaQuantidade, novoConteudo, solicitacao.lista_id]);
        
        db.run(`UPDATE solicitacoes SET status = 'aprovado', data_autorizacao = CURRENT_TIMESTAMP WHERE id = ?`, 
          [req.params.id]);
        
        res.json({ success: true, mensagem: `${quantidadeReal} fichas entregues!` });
      });
    } else {
      db.run(`UPDATE solicitacoes SET status = 'recusado' WHERE id = ?`, [req.params.id]);
      res.json({ success: true });
    }
  });
});

// ========== RELATÓRIOS ==========

app.get('/api/admin/relatorio-usuarios', verificarAdmin, (req, res) => {
  db.all(`
    SELECT u.id, u.nome, u.email, u.whatsapp, u.data_cadastro,
      (SELECT COUNT(*) FROM minhas_listas WHERE usuario_id = u.id) as total_listas_obtidas,
      (SELECT COUNT(*) FROM solicitacoes WHERE usuario_id = u.id AND status = 'aprovado') as solicitacoes_aprovadas
    FROM usuarios u WHERE u.tipo = 'usuario' ORDER BY u.id DESC`, (err, rows) => {
    if (err) return res.status(500).json({ erro: err.message });
    res.json(rows);
  });
});

// ========== AGENDAMENTOS ==========

const clients = [];

app.get('/api/events', (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders();
  const clientId = Date.now();
  clients.push({ id: clientId, res });
  req.on('close', () => {
    const index = clients.findIndex(c => c.id === clientId);
    if (index !== -1) clients.splice(index, 1);
  });
});

function broadcastEvent(event, data) {
  clients.forEach(client => {
    client.res.write(`event: ${event}\n`);
    client.res.write(`data: ${JSON.stringify(data)}\n\n`);
  });
}

function gerarHorarios() {
  const horarios = [];
  for (let hora = 8; hora <= 17; hora++) {
    for (let min of [0, 10, 20, 30, 40, 50]) {
      if (hora === 17 && min > 0) continue;
      horarios.push(`${hora.toString().padStart(2, '0')}:${min.toString().padStart(2, '0')}`);
    }
  }
  return horarios;
}

function validarHorario(dataHora, existentes, ignorar = null) {
  const d = new Date(dataHora);
  const hora = d.getHours();
  const min = d.getMinutes();
  
  if (hora < 8 || hora > 17) return { ok: false, erro: 'Horário fora do comercial! 08:00 às 17:00' };
  if (hora === 17 && min > 0) return { ok: false, erro: 'Último horário é 17:00' };
  if (min % 10 !== 0) return { ok: false, erro: 'Horário deve ser a cada 10 minutos' };
  
  for (const f of existentes) {
    if (ignorar && f.id === ignorar) continue;
    if (f.status === 'encerrado') continue;
    const fd = new Date(f.horarioAgendado);
    if (fd.getTime() === d.getTime()) return { ok: false, erro: `Horário já ocupado` };
    if (Math.abs(fd - d) / 60000 < 10 && Math.abs(fd - d) / 60000 > 0) {
      return { ok: false, erro: `Intervalo mínimo de 10 minutos` };
    }
  }
  return { ok: true };
}

app.get('/api/horarios-disponiveis', (req, res) => {
  const { data } = req.query;
  if (!data) return res.json({ horarios: [] });
  
  db.all('SELECT * FROM fichas', (err, existentes) => {
    if (err) return res.status(500).json({ error: err.message });
    const disponiveis = [];
    for (const hora of gerarHorarios()) {
      if (validarHorario(`${data}T${hora}:00`, existentes).ok) {
        disponiveis.push(hora);
      }
    }
    res.json({ horarios: disponiveis });
  });
});

app.get('/api/fichas', (req, res) => {
  db.all('SELECT * FROM fichas ORDER BY horarioAgendado ASC, id ASC', (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.post('/api/fichas', (req, res) => {
  const { nomeCliente, telefoneCliente, assunto, nomeGerente, horarioAgendado, vulgo, zap, banco } = req.body;
  
  db.all('SELECT * FROM fichas', (err, existentes) => {
    if (err) return res.status(500).json({ error: err.message });
    
    const val = validarHorario(horarioAgendado, existentes);
    if (!val.ok) return res.status(400).json({ error: val.erro });
    
    const horarioChegada = new Date().toISOString();
    db.run(
      `INSERT INTO fichas (nomeCliente, telefoneCliente, assunto, nomeGerente, horarioAgendado, vulgo, zap, status, horarioChegada, observacao, atendidoPor, dataEncerramento, comentario, banco)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
      [nomeCliente, telefoneCliente || '', assunto, nomeGerente || 'MIA FIOD', horarioAgendado, vulgo, zap, 'aguardando', horarioChegada, '', '', '', '', banco || 'pagbank'],
      function (err2) {
        if (err2) return res.status(500).json({ error: err2.message });
        db.get('SELECT * FROM fichas WHERE id = ?', [this.lastID], (err3, ficha) => {
          if (!err3 && ficha) broadcastEvent('nova-ficha', ficha);
        });
        res.json({ id: this.lastID, success: true });
      }
    );
  });
});

app.put('/api/fichas/:id/iniciar', (req, res) => {
  db.run('UPDATE fichas SET status = "em_andamento", atendidoPor = "MIA FIOD" WHERE id = ?', [req.params.id], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    db.get('SELECT * FROM fichas WHERE id = ?', [req.params.id], (err2, ficha) => {
      if (!err2 && ficha) broadcastEvent('status-alterado', ficha);
    });
    res.json({ success: true });
  });
});

app.put('/api/fichas/:id/adiantar', (req, res) => {
  db.get('SELECT * FROM fichas WHERE id = ?', [req.params.id], (err, ficha) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!ficha) return res.status(404).json({ error: 'Ficha não encontrada' });
    
    const dataFicha = ficha.horarioAgendado.split('T')[0];
    db.all('SELECT * FROM fichas WHERE id != ?', [req.params.id], (err2, outras) => {
      if (err2) return res.status(500).json({ error: err2.message });
      
      for (const hora of gerarHorarios()) {
        const dataHora = `${dataFicha}T${hora}:00`;
        if (validarHorario(dataHora, outras, parseInt(req.params.id)).ok) {
          db.run('UPDATE fichas SET horarioAgendado = ? WHERE id = ?', [dataHora, req.params.id], function(err3) {
            if (err3) return res.status(500).json({ error: err3.message });
            db.get('SELECT * FROM fichas WHERE id = ?', [req.params.id], (err4, fichaAtualizada) => {
              if (!err4 && fichaAtualizada) broadcastEvent('status-alterado', fichaAtualizada);
            });
            res.json({ success: true });
          });
          return;
        }
      }
      res.status(400).json({ error: 'Não foi possível adiantar.' });
    });
  });
});

app.put('/api/fichas/:id/pausar', (req, res) => {
  const { comentario } = req.body;
  db.run('UPDATE fichas SET status = "pausado", comentario = ? WHERE id = ?', [comentario || 'Pausado', req.params.id], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    db.get('SELECT * FROM fichas WHERE id = ?', [req.params.id], (err2, ficha) => {
      if (!err2 && ficha) broadcastEvent('status-alterado', ficha);
    });
    res.json({ success: true });
  });
});

app.put('/api/fichas/:id/retomar', (req, res) => {
  db.run('UPDATE fichas SET status = "aguardando" WHERE id = ?', [req.params.id], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    db.get('SELECT * FROM fichas WHERE id = ?', [req.params.id], (err2, ficha) => {
      if (!err2 && ficha) broadcastEvent('status-alterado', ficha);
    });
    res.json({ success: true });
  });
});

app.put('/api/fichas/:id/pendente', (req, res) => {
  const { comentario } = req.body;
  db.run('UPDATE fichas SET status = "pendente", comentario = ? WHERE id = ?', [comentario || 'Aguardando', req.params.id], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    db.get('SELECT * FROM fichas WHERE id = ?', [req.params.id], (err2, ficha) => {
      if (!err2 && ficha) broadcastEvent('status-alterado', ficha);
    });
    res.json({ success: true });
  });
});

app.put('/api/fichas/:id/comentario', (req, res) => {
  const { comentario } = req.body;
  db.run('UPDATE fichas SET comentario = ? WHERE id = ?', [comentario, req.params.id], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    db.get('SELECT * FROM fichas WHERE id = ?', [req.params.id], (err2, ficha) => {
      if (!err2 && ficha) broadcastEvent('status-alterado', ficha);
    });
    res.json({ success: true });
  });
});

app.put('/api/fichas/:id/encerrar', (req, res) => {
  const { observacao } = req.body;
  db.run('UPDATE fichas SET status = "encerrado", observacao = ?, dataEncerramento = ? WHERE id = ?',
    [observacao, new Date().toISOString(), req.params.id], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    db.get('SELECT * FROM fichas WHERE id = ?', [req.params.id], (err2, ficha) => {
      if (!err2 && ficha) broadcastEvent('status-alterado', ficha);
    });
    res.json({ success: true });
  });
});

app.delete('/api/fichas/:id', (req, res) => {
  db.run('DELETE FROM fichas WHERE id = ?', [req.params.id], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    if (this.changes === 0) return res.status(404).json({ error: 'Ficha não encontrada' });
    broadcastEvent('ficha-excluida', { id: parseInt(req.params.id) });
    res.json({ success: true });
  });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`🔥 Servidor MIA FIOD rodando na porta ${PORT}`);
});
