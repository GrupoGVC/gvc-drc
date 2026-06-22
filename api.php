<?php
// ═══════════════════════════════════════════════════
// GVC DRC — API REST v3.1.0
// Perfis: gestor | consultor | operacional | financeiro | diretor
// ═══════════════════════════════════════════════════

require_once __DIR__ . '/config.php';

$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
if (in_array($origin, CORS_ORIGINS, true)) {
    header('Access-Control-Allow-Origin: ' . $origin);
    header('Access-Control-Allow-Credentials: true');
}
header('Access-Control-Allow-Methods: GET, POST, DELETE, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');
header('Content-Type: application/json; charset=utf-8');
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') { http_response_code(204); exit; }

// ── PERMISSÕES POR PERFIL ─────────────────────────────────
const ROLE_PERMISSIONS = [
    'gestor'       => ['all'],
    'diretor'      => ['view_all', 'aprovar', 'reprovar', 'view_custos', 'view_margens'],
    'financeiro'   => ['view_all', 'view_custos', 'view_margens'],
    'consultor'    => ['create_drc', 'edit_own_drc', 'view_all', 'submit_drc'],
    'operacional'  => ['view_operacional', 'confirmar_execucao', 'validar_custos'],
];

// Status que cada perfil pode atribuir
const ROLE_STATUS_FLOW = [
    'gestor'      => ['rascunho','enviado','em_analise','aprovado','reprovado','cancelado','aguardando_execucao','validacao_custos','concluido'],
    'diretor'     => ['aprovado','reprovado'],
    'financeiro'  => [],
    'consultor'   => ['rascunho','enviado'],
    'operacional' => ['validacao_custos','concluido'],
];

function db(): PDO {
    static $pdo;
    if (!$pdo) {
        $dsn = 'mysql:host='.DB_HOST.';dbname='.DB_NAME.';charset='.DB_CHARSET;
        $pdo = new PDO($dsn, DB_USER, DB_PASS, [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        ]);
    }
    return $pdo;
}
function ok($data=null,int $code=200):void { http_response_code($code); echo json_encode(['ok'=>true,'data'=>$data],JSON_UNESCAPED_UNICODE); exit; }
function err(string $msg,int $code=400):void { http_response_code($code); echo json_encode(['ok'=>false,'error'=>$msg],JSON_UNESCAPED_UNICODE); exit; }
function body():array { $r=file_get_contents('php://input'); return $r?(json_decode($r,true)??[]):[]; }
function getToken():?string {
    $h=$_SERVER['HTTP_AUTHORIZATION']??'';
    if(preg_match('/^Bearer\s+(.+)$/i',$h,$m)) return $m[1];
    return $_COOKIE['gvc_token']??null;
}
function currentUser():?array {
    $token=getToken(); if(!$token) return null;
    $stmt=db()->prepare('SELECT u.id,u.nome,u.email,u.role,u.unidade FROM sessoes s JOIN usuarios u ON u.id=s.usuario_id WHERE s.token=? AND s.expires_at>NOW() AND u.ativo=1');
    $stmt->execute([$token]); return $stmt->fetch()?:null;
}
function require_auth(array $roles=[]):array {
    $u=currentUser(); if(!$u) err('Não autenticado',401);
    if($roles && !in_array($u['role'],$roles,true)) err('Acesso negado para perfil: '.$u['role'],403);
    return $u;
}
function has_perm(array $user, string $perm):bool {
    $perms = ROLE_PERMISSIONS[$user['role']] ?? [];
    return in_array('all',$perms) || in_array($perm,$perms);
}
function can_set_status(array $user, string $status):bool {
    $allowed = ROLE_STATUS_FLOW[$user['role']] ?? [];
    return in_array($status,$allowed);
}
// Campos sensíveis de custo/margem — ocultos para operacional e diretor
function maybe_hide_financials(array $drc, array $user): array {
    if(in_array($user['role'],['operacional'])) {
        // Remove financial fields
        $hide = ['custoTotal','pvTotal','margem','margemPct','totalCustoColeta',
                 'totalCustoDest','totalCustoLoc','totalCustoOp','impostos',
                 'pvColeta','pvDest','pvLoc','pvOp'];
        foreach($hide as $f) unset($drc[$f]);
        // Also hide unit costs in coletas/destinacoes
        foreach(($drc['coletas']??[]) as &$c) { unset($c['custoUnitario'],$c['custo'],$c['pvUnit']); }
        foreach(($drc['destinacoes']??[]) as &$d) { unset($d['custoUnit'],$d['pvUnit']); }
    }
    return $drc;
}

$action=$_GET['action']??body()['action']??'';
$method=$_SERVER['REQUEST_METHOD'];

// ── LOGIN ─────────────────────────────────────────────────
if($action==='login' && $method==='POST'){
    $b=body(); $email=trim($b['email']??''); $senha=$b['senha']??'';
    if(!$email||!$senha) err('E-mail e senha obrigatórios');
    $stmt=db()->prepare('SELECT * FROM usuarios WHERE email=? AND ativo=1');
    $stmt->execute([$email]); $u=$stmt->fetch();
    if(!$u||!password_verify($senha,$u['senha_hash'])) err('E-mail ou senha incorretos',401);
    $token=bin2hex(random_bytes(32));
    $exp=date('Y-m-d H:i:s',time()+SESSION_TTL);
    db()->prepare('INSERT INTO sessoes (token,usuario_id,expires_at) VALUES (?,?,?)')->execute([$token,$u['id'],$exp]);
    setcookie('gvc_token',$token,['expires'=>time()+SESSION_TTL,'path'=>'/','secure'=>true,'httponly'=>true,'samesite'=>'None']);
    ok(['token'=>$token,'nome'=>$u['nome'],'role'=>$u['role'],'unidade'=>$u['unidade']??'','permissions'=>ROLE_PERMISSIONS[$u['role']]??[]]);
}
// ── LOGOUT ───────────────────────────────────────────────
elseif($action==='logout' && $method==='POST'){
    $t=getToken(); if($t) db()->prepare('DELETE FROM sessoes WHERE token=?')->execute([$t]);
    setcookie('gvc_token','',['expires'=>1,'path'=>'/','samesite'=>'None','secure'=>true]);
    ok();
}
// ── ME ───────────────────────────────────────────────────
elseif($action==='me' && $method==='GET'){
    $u=require_auth();
    $pCustom = $u['permissoes_custom'] ?? null;
    $pDecoded = $pCustom ? (json_decode($pCustom, true) ?? []) : null;
    ok(['nome'=>$u['nome'],'role'=>$u['role'],'email'=>$u['email'],'unidade'=>$u['unidade']??'',
        'permissions'=>ROLE_PERMISSIONS[$u['role']]??[],
        'permissoes_custom'=>$pDecoded]);
}
// ── LIST DRCs ────────────────────────────────────────────
elseif($action==='list_drcs' && $method==='GET'){
    $u=require_auth();
    $where='1=1';
    if($u['role']==='operacional') $where.=" AND status IN ('aguardando_execucao','validacao_custos')";
    $rows=db()->query("SELECT id,numero,cliente,empresa,lead_seg,consultor,data_drc,munUF,cluster,unidade,status,updated_at,created_at FROM drcs WHERE $where ORDER BY updated_at DESC")->fetchAll();
    ok($rows);
}
// ── GET DRC ──────────────────────────────────────────────
elseif($action==='get_drc' && $method==='GET'){
    $u=require_auth(); $id=$_GET['id']??''; if(!$id) err('ID obrigatório');
    $stmt=db()->prepare('SELECT * FROM drcs WHERE id=?'); $stmt->execute([$id]); $row=$stmt->fetch();
    if(!$row) err('DRC não encontrado',404);
    if($u['role']==='operacional' && !in_array($row['status'],['aguardando_execucao','validacao_custos'])) err('Acesso negado',403);
    $drc=json_decode($row['data_json']??'{}',true)??$row;
    $drc=maybe_hide_financials($drc,$u);
    ok($drc);
}
// ── SAVE DRC ─────────────────────────────────────────────
elseif($action==='save_drc' && $method==='POST'){
    $u=require_auth(); $b=body(); $drc=$b['drc']??null;
    if(!$drc||!($drc['id']??null)) err('DRC inválido');
    $id=$drc['id']; $status=$drc['status']??'rascunho';
    // Check if role can set this status
    if(!can_set_status($u,$status)) err("Perfil '{$u['role']}' não pode definir status '$status'",403);
    // Financeiro e Diretor não podem editar
    if(in_array($u['role'],['financeiro','diretor'])) err('Perfil sem permissão para editar DRCs',403);
    $json=json_encode($drc,JSON_UNESCAPED_UNICODE);
    $stmt=db()->prepare('INSERT INTO drcs (id,numero,cliente,empresa,lead_seg,consultor,data_drc,munUF,cluster,unidade,status,data_json) VALUES (?,?,?,?,?,?,?,?,?,?,?,?) ON DUPLICATE KEY UPDATE numero=VALUES(numero),cliente=VALUES(cliente),empresa=VALUES(empresa),lead_seg=VALUES(lead_seg),consultor=VALUES(consultor),data_drc=VALUES(data_drc),munUF=VALUES(munUF),cluster=VALUES(cluster),unidade=VALUES(unidade),status=VALUES(status),data_json=VALUES(data_json)');
    $stmt->execute([$id,$drc['numero']??null,$drc['cliente']??null,$drc['empresa']??null,$drc['lead']??null,$drc['consultor']??null,$drc['data']??null,$drc['munUF']??null,$drc['cluster']??null,$drc['unidadeAtendimento']??null,$status,$json]);
    if(!empty($drc['statusHistorico'])){
        $last=end($drc['statusHistorico']);
        db()->prepare('INSERT INTO drcs_status_historico (drc_id,status,data_hora,autor,justificativa) VALUES (?,?,?,?,?)')->execute([$id,$last['status']??$status,$last['data']??date('Y-m-d H:i:s'),$last['autor']??'',$last['justificativa']??'']);
    }
    ok(['id'=>$id]);
}
// ── DELETE DRC ───────────────────────────────────────────
elseif($action==='delete_drc' && $method==='DELETE'){
    require_auth(['gestor']); $id=$_GET['id']??body()['id']??''; if(!$id) err('ID obrigatório');
    db()->prepare('DELETE FROM drcs WHERE id=?')->execute([$id]); ok();
}
// ── CADASTROS ────────────────────────────────────────────
elseif($action==='get_cadastros' && $method==='GET'){
    require_auth();
    $rows=db()->query('SELECT tipo,dados FROM cadastros WHERE dados IS NOT NULL')->fetchAll();
    $out=[]; foreach($rows as $r) $out[$r['tipo']]=json_decode($r['dados'],true);
    ok($out);
}
elseif($action==='save_cadastros' && $method==='POST'){
    require_auth(['gestor']); $b=body(); $cadastros=$b['cadastros']??null; if(!$cadastros) err('Dados inválidos');
    $stmtUpd = db()->prepare('UPDATE cadastros SET dados=? WHERE tipo=?');
    $stmtIns = db()->prepare('INSERT INTO cadastros (tipo, valor, dados) VALUES (?,\'\',?)');
    foreach($cadastros as $tipo=>$lista) {
        $json = json_encode($lista, JSON_UNESCAPED_UNICODE);
        $stmtUpd->execute([$json, $tipo]);
        if($stmtUpd->rowCount() === 0) {
            try { $stmtIns->execute([$tipo, $json]); } catch(\PDOException $e) { /* já existe, ignorar */ }
        }
    }
    ok();
}
// ── USUARIOS ─────────────────────────────────────────────
elseif($action==='list_usuarios' && $method==='GET'){
    require_auth(['gestor']);
    $rows = db()->query('SELECT id,nome,email,role,unidade,ativo,permissoes_custom,created_at FROM usuarios ORDER BY nome')->fetchAll();
    foreach($rows as &$row) {
        $row['permissoes_custom'] = $row['permissoes_custom'] ? json_decode($row['permissoes_custom'], true) : null;
    }
    ok($rows);
}
elseif($action==='list_consultores' && $method==='GET'){
    require_auth(); // qualquer usuário autenticado
    $rows=db()->query("SELECT nome FROM usuarios WHERE ativo=1 AND role IN ('consultor','gestor') ORDER BY nome")->fetchAll();
    ok(array_column($rows,'nome'));
}
elseif($action==='create_usuario' && $method==='POST'){
    require_auth(['gestor']); $b=body();
    $nome=$b['nome']??''; $email=$b['email']??''; $senha=$b['senha']??''; $role=$b['role']??'consultor'; $unidade=$b['unidade']??'';
    if(!$nome||!$email||!$senha) err('nome, email e senha obrigatórios');
    $roles_validos=['gestor','diretor','financeiro','consultor','operacional'];
    if(!in_array($role,$roles_validos)) err('Role inválido');
    try {
        db()->prepare('INSERT INTO usuarios (nome,email,senha_hash,role,unidade) VALUES (?,?,?,?,?)')->execute([$nome,$email,password_hash($senha,PASSWORD_BCRYPT),$role,$unidade]);
        ok(['id'=>db()->lastInsertId()]);
    } catch(\PDOException $e) { err('E-mail já cadastrado'); }
}
elseif($action==='update_usuario' && $method==='POST'){
    require_auth(['gestor']); $b=body();
    $id=$b['id']??0; $nome=$b['nome']??''; $email=$b['email']??''; $role=$b['role']??''; $unidade=$b['unidade']??'';
    if(!$id||!$nome||!$email||!$role) err('Dados incompletos');
    $roles_validos=['gestor','diretor','financeiro','consultor','operacional'];
    if(!in_array($role,$roles_validos)) err('Role inválido');
    $stmt=db()->prepare('UPDATE usuarios SET nome=?,email=?,role=?,unidade=? WHERE id=?');
    $stmt->execute([$nome,$email,$role,$unidade,$id]);
    if(!empty($b['nova_senha']) && strlen($b['nova_senha'])>=6)
        db()->prepare('UPDATE usuarios SET senha_hash=? WHERE id=?')->execute([password_hash($b['nova_senha'],PASSWORD_BCRYPT),$id]);
    ok();
}
elseif($action==='save_permissoes' && $method==='POST'){
    require_auth(['gestor']); $b=body();
    $id=$b['id']??0; $perm=$b['permissoes_custom']??null;
    if(!$id) err('ID obrigatório');
    $json = $perm !== null ? json_encode($perm, JSON_UNESCAPED_UNICODE) : null;
    db()->prepare('UPDATE usuarios SET permissoes_custom=? WHERE id=?')->execute([$json, $id]);
    ok();
}
elseif($action==='toggle_usuario' && $method==='POST'){
    require_auth(['gestor']); $id=body()['id']??0;
    db()->prepare('UPDATE usuarios SET ativo=1-ativo WHERE id=?')->execute([$id]); ok();
}
elseif($action==='delete_usuario' && $method==='DELETE'){
    require_auth(['gestor']); $id=$_GET['id']??body()['id']??0;
    db()->prepare('DELETE FROM sessoes WHERE usuario_id=?')->execute([$id]);
    db()->prepare('DELETE FROM usuarios WHERE id=?')->execute([$id]); ok();
}
elseif($action==='change_senha' && $method==='POST'){
    $u=require_auth(); $b=body(); $atual=$b['senha_atual']??''; $nova=$b['senha_nova']??'';
    if(!$atual||!$nova||strlen($nova)<6) err('Dados inválidos');
    $stmt=db()->prepare('SELECT senha_hash FROM usuarios WHERE id=?'); $stmt->execute([$u['id']]); $row=$stmt->fetch();
    if(!password_verify($atual,$row['senha_hash'])) err('Senha atual incorreta');
    db()->prepare('UPDATE usuarios SET senha_hash=? WHERE id=?')->execute([password_hash($nova,PASSWORD_BCRYPT),$u['id']]); ok();
}
// ── CONTADORES ───────────────────────────────────────────
elseif($action==='contadores' && $method==='GET'){
    require_auth();
    $row=db()->query("SELECT SUM(status='aguardando_execucao') AS aguardando,SUM(status='validacao_custos') AS validacao,SUM(status='concluido') AS concluido FROM drcs")->fetch();
    ok($row);
}
elseif($action==='next_numero' && $method==='GET'){
    require_auth();
    $ano = date('Y');
    // Upsert e retorna próximo número de forma atômica
    db()->prepare("INSERT INTO drc_sequence (ano, ultimo) VALUES (?, 1) ON DUPLICATE KEY UPDATE ultimo = ultimo + 1")->execute([$ano]);
    $row = db()->prepare("SELECT ultimo FROM drc_sequence WHERE ano = ?")->execute([$ano]) ? db()->query("SELECT ultimo FROM drc_sequence WHERE ano = $ano")->fetch() : null;
    // Use LAST_INSERT_ID trick for atomicity
    db()->prepare("UPDATE drc_sequence SET ultimo = LAST_INSERT_ID(ultimo) WHERE ano = ?")->execute([$ano]);
    $seq = db()->query("SELECT LAST_INSERT_ID() as n")->fetch();
    $num = str_pad($seq['n'], 4, '0', STR_PAD_LEFT);
    ok(['numero' => "DRC-{$ano}-{$num}", 'sequencia' => (int)$seq['n']]);
}
// ═══════════════════════════════════════════════════════════
// MÓDULO ATIVOS LOGÍSTICOS — v3.1.0
// 2026-06-22 — feat: controle de ativos logísticos
//   Endpoints: list_unidades, list_ativos, get_ativo,
//              save_ativo, delete_ativo, transfer_ativo,
//              list_transferencias, save_inventario,
//              list_inventarios, upload_foto_inventario,
//              upload_logomarca_ativo
// ═══════════════════════════════════════════════════════════

// ── LIST UNIDADES (dropdown) ──────────────────────────────
elseif($action==='list_unidades' && $method==='GET'){
    require_auth();
    $rows=db()->query('SELECT id,nome,codigo,empresa,municipio,uf FROM unidades_operacionais WHERE ativo=1 ORDER BY nome')->fetchAll();
    ok($rows);
}
// ── LIST ATIVOS ───────────────────────────────────────────
elseif($action==='list_ativos' && $method==='GET'){
    $u=require_auth(['gestor','diretor','financeiro','operacional']);
    $where=['1=1']; $params=[];
    // Operacional só vê ativos da própria unidade
    if($u['role']==='operacional'){ $where[]='uo.nome=?'; $params[]=$u['unidade']; }
    // Filtros opcionais
    if(!empty($_GET['unidade_id'])){ $where[]='a.unidade_id=?'; $params[]=(int)$_GET['unidade_id']; }
    if(!empty($_GET['tipo']))      { $where[]='a.tipo=?';       $params[]=$_GET['tipo']; }
    if(!empty($_GET['status']))    { $where[]='a.status=?';     $params[]=$_GET['status']; }
    if(!empty($_GET['ownership'])) { $where[]='a.ownership=?';  $params[]=$_GET['ownership']; }
    $w=implode(' AND ',$where);
    $stmt=db()->prepare(
        "SELECT a.id,a.codigo,a.tipo,a.descricao,a.numero_interno,
                a.placa,a.marca,a.modelo,a.ano_fabricacao,a.ano_modelo,
                a.tipo_carroceria,a.ownership,a.status,a.vencimento_aluguel,
                a.valor_estimado,a.logomarca_url,
                a.unidade_id,uo.nome AS unidade_nome,uo.codigo AS unidade_codigo,
                (SELECT condicao FROM ativos_inventarios i
                 WHERE i.ativo_id=a.id ORDER BY i.data_inventario DESC LIMIT 1) AS ultima_condicao,
                (SELECT data_inventario FROM ativos_inventarios i
                 WHERE i.ativo_id=a.id ORDER BY i.data_inventario DESC LIMIT 1) AS ultimo_inventario,
                a.updated_at
         FROM ativos a
         LEFT JOIN unidades_operacionais uo ON uo.id=a.unidade_id
         WHERE $w
         ORDER BY a.tipo, a.codigo"
    );
    $stmt->execute($params);
    ok($stmt->fetchAll());
}
// ── GET ATIVO ─────────────────────────────────────────────
elseif($action==='get_ativo' && $method==='GET'){
    $u=require_auth(['gestor','diretor','financeiro','operacional']);
    $id=(int)($_GET['id']??0); if(!$id) err('ID obrigatório');
    $stmt=db()->prepare(
        'SELECT a.*,uo.nome AS unidade_nome,uo.codigo AS unidade_codigo
         FROM ativos a
         LEFT JOIN unidades_operacionais uo ON uo.id=a.unidade_id
         WHERE a.id=?'
    );
    $stmt->execute([$id]); $ativo=$stmt->fetch();
    if(!$ativo) err('Ativo não encontrado',404);
    if($u['role']==='operacional' && $ativo['unidade_nome']!==$u['unidade']) err('Acesso negado',403);
    // Decodificar JSON de tanques de combustível
    if($ativo['tanques_combustivel_litros'])
        $ativo['tanques_combustivel_litros']=json_decode($ativo['tanques_combustivel_litros'],true);
    ok($ativo);
}
// ── SAVE ATIVO (create / update) ──────────────────────────
elseif($action==='save_ativo' && $method==='POST'){
    require_auth(['gestor']); $b=body();
    $tipo=trim($b['tipo']??''); $descricao=trim($b['descricao']??'');
    if(!in_array($tipo,['caminhao','roll_on','poliguindaste'],true)) err('Tipo inválido');
    if(!$descricao) err('Descrição obrigatória');
    $id=(int)($b['id']??0);
    // Serializar tanques de combustível
    $tanques=$b['tanques_combustivel_litros']??null;
    $tanquesJson=$tanques
        ? json_encode(array_values((array)$tanques),JSON_UNESCAPED_UNICODE)
        : null;
    $f=[
        'tipo'                       => $tipo,
        'descricao'                  => $descricao,
        'numero_interno'             => $b['numero_interno']??null,
        'placa'                      => $b['placa']??null,
        'chassi'                     => $b['chassi']??null,
        'renavam'                    => $b['renavam']??null,
        'marca'                      => $b['marca']??null,
        'modelo'                     => $b['modelo']??null,
        'cor'                        => $b['cor']??null,
        'tipo_carroceria'            => $b['tipo_carroceria']??null,
        'ano_fabricacao'             => $b['ano_fabricacao']??null,
        'ano_modelo'                 => $b['ano_modelo']??null,
        'tipo_combustivel'           => $b['tipo_combustivel']??null,
        'num_tanques_combustivel'    => $b['num_tanques_combustivel']??null,
        'tanques_combustivel_litros' => $tanquesJson,
        'pbt_kg'                     => $b['pbt_kg']??null,
        'cmt_kg'                     => $b['cmt_kg']??null,
        'capacidade_carga_kg'        => $b['capacidade_carga_kg']??null,
        'capacidade_m3'              => $b['capacidade_m3']??null,
        'capacidade_bombonas'        => $b['capacidade_bombonas']??null,
        'comprimento'                => $b['comprimento']??null,
        'largura'                    => $b['largura']??null,
        'altura'                     => $b['altura']??null,
        'impl_comprimento'           => $b['impl_comprimento']??null,
        'impl_largura'               => $b['impl_largura']??null,
        'impl_altura'                => $b['impl_altura']??null,
        'numero_serie'               => $b['numero_serie']??null,
        'fabricante'                 => $b['fabricante']??null,
        'volume_m3'                  => $b['volume_m3']??null,
        'ownership'                  => $b['ownership']??'proprio',
        'fornecedor_aluguel'         => $b['fornecedor_aluguel']??null,
        'contrato_aluguel'           => $b['contrato_aluguel']??null,
        'vencimento_aluguel'         => $b['vencimento_aluguel']??null,
        'unidade_id'                 => $b['unidade_id']??null,
        'status'                     => $b['status']??'ativo',
        'valor_estimado'             => $b['valor_estimado']??null,
        'data_aquisicao'             => $b['data_aquisicao']??null,
        'observacoes'                => $b['observacoes']??null,
    ];
    if($id){
        // UPDATE
        $sets=implode(',',array_map(fn($k)=>"$k=?",array_keys($f)));
        $vals=array_values($f); $vals[]=$id;
        db()->prepare("UPDATE ativos SET $sets WHERE id=?")->execute($vals);
        ok(['id'=>$id]);
    } else {
        // INSERT — gera código sequencial por tipo: CAM-0001, ROL-0001, POL-0001
        $px=['caminhao'=>'CAM','roll_on'=>'ROL','poliguindaste'=>'POL'][$tipo];
        $stmt=db()->prepare("SELECT MAX(CAST(SUBSTRING(codigo,5) AS UNSIGNED)) AS n FROM ativos WHERE tipo=?");
        $stmt->execute([$tipo]); $row=$stmt->fetch();
        $next=(int)($row['n']??0)+1;
        $codigo=$px.'-'.str_pad($next,4,'0',STR_PAD_LEFT);
        $f['codigo']=$codigo;
        $cols=implode(',',array_keys($f));
        $ph=implode(',',array_fill(0,count($f),'?'));
        db()->prepare("INSERT INTO ativos ($cols) VALUES ($ph)")->execute(array_values($f));
        ok(['id'=>(int)db()->lastInsertId(),'codigo'=>$codigo]);
    }
}
// ── DELETE ATIVO (baixa — soft delete) ────────────────────
elseif($action==='delete_ativo' && $method==='POST'){
    require_auth(['gestor']); $id=(int)(body()['id']??0);
    if(!$id) err('ID obrigatório');
    db()->prepare("UPDATE ativos SET status='baixado' WHERE id=?")->execute([$id]);
    ok();
}
// ── TRANSFER ATIVO ────────────────────────────────────────
elseif($action==='transfer_ativo' && $method==='POST'){
    $u=require_auth(['gestor']); $b=body();
    $ativoId=(int)($b['ativo_id']??0); $destId=(int)($b['unidade_destino_id']??0);
    if(!$ativoId||!$destId) err('ativo_id e unidade_destino_id obrigatórios');
    // Busca situação atual do ativo
    $stmtA=db()->prepare(
        'SELECT a.unidade_id,uo.nome AS unidade_nome
         FROM ativos a LEFT JOIN unidades_operacionais uo ON uo.id=a.unidade_id
         WHERE a.id=?'
    );
    $stmtA->execute([$ativoId]); $ativo=$stmtA->fetch();
    if(!$ativo) err('Ativo não encontrado',404);
    // Busca unidade destino
    $stmtD=db()->prepare('SELECT id,nome FROM unidades_operacionais WHERE id=?');
    $stmtD->execute([$destId]); $dest=$stmtD->fetch();
    if(!$dest) err('Unidade de destino não encontrada',404);
    // Transação: registra histórico e atualiza unidade
    $pdo=db(); $pdo->beginTransaction();
    try {
        $pdo->prepare(
            'INSERT INTO ativos_transferencias
             (ativo_id,unidade_origem_id,unidade_destino_id,unidade_origem_nome,
              unidade_destino_nome,data_transferencia,motivo,usuario_id,usuario_nome,observacoes)
             VALUES (?,?,?,?,?,?,?,?,?,?)'
        )->execute([
            $ativoId, $ativo['unidade_id'], $destId,
            $ativo['unidade_nome'], $dest['nome'],
            $b['data_transferencia']??date('Y-m-d H:i:s'),
            $b['motivo']??null, $u['id'], $u['nome'], $b['observacoes']??null
        ]);
        $pdo->prepare('UPDATE ativos SET unidade_id=? WHERE id=?')->execute([$destId,$ativoId]);
        $pdo->commit();
        ok(['ativo_id'=>$ativoId,'unidade_destino'=>$dest['nome']]);
    } catch(\Throwable $e){ $pdo->rollBack(); err('Erro ao registrar transferência: '.$e->getMessage()); }
}
// ── LIST TRANSFERENCIAS ───────────────────────────────────
elseif($action==='list_transferencias' && $method==='GET'){
    require_auth(['gestor','diretor','financeiro','operacional']);
    $id=(int)($_GET['ativo_id']??0); if(!$id) err('ativo_id obrigatório');
    $stmt=db()->prepare(
        'SELECT * FROM ativos_transferencias WHERE ativo_id=? ORDER BY data_transferencia DESC'
    );
    $stmt->execute([$id]); ok($stmt->fetchAll());
}
// ── SAVE INVENTARIO ───────────────────────────────────────
elseif($action==='save_inventario' && $method==='POST'){
    $u=require_auth(['gestor','operacional']); $b=body();
    $ativoId=(int)($b['ativo_id']??0); $condicao=$b['condicao']??'';
    if(!$ativoId) err('ativo_id obrigatório');
    if(!in_array($condicao,['otimo','bom','regular','ruim','inoperante'],true)) err('Condição inválida');
    // Busca ativo + unidade para validar permissão e capturar snapshot
    $stmtA=db()->prepare(
        'SELECT a.unidade_id,uo.nome AS unidade_nome
         FROM ativos a LEFT JOIN unidades_operacionais uo ON uo.id=a.unidade_id
         WHERE a.id=?'
    );
    $stmtA->execute([$ativoId]); $ativo=$stmtA->fetch();
    if(!$ativo) err('Ativo não encontrado',404);
    if($u['role']==='operacional' && $ativo['unidade_nome']!==$u['unidade'])
        err('Acesso negado — ativo fora da sua unidade',403);
    db()->prepare(
        'INSERT INTO ativos_inventarios
         (ativo_id,unidade_id,unidade_nome,data_inventario,usuario_id,usuario_nome,condicao,observacoes)
         VALUES (?,?,?,?,?,?,?,?)'
    )->execute([
        $ativoId, $ativo['unidade_id'], $ativo['unidade_nome'],
        $b['data_inventario']??date('Y-m-d H:i:s'),
        $u['id'], $u['nome'], $condicao, $b['observacoes']??null
    ]);
    ok(['id'=>(int)db()->lastInsertId()]);
}
// ── LIST INVENTARIOS ──────────────────────────────────────
elseif($action==='list_inventarios' && $method==='GET'){
    require_auth(['gestor','diretor','financeiro','operacional']);
    $id=(int)($_GET['ativo_id']??0); if(!$id) err('ativo_id obrigatório');
    $stmt=db()->prepare(
        "SELECT ai.*,
            (SELECT JSON_ARRAYAGG(
                JSON_OBJECT(
                    'id',f.id,
                    'nome_arquivo',f.nome_arquivo,
                    'url',CONCAT('https://api.drc-gvc.tech',f.caminho)
                ))
             FROM ativos_inventario_fotos f WHERE f.inventario_id=ai.id) AS fotos
         FROM ativos_inventarios ai
         WHERE ai.ativo_id=?
         ORDER BY ai.data_inventario DESC"
    );
    $stmt->execute([$id]); $rows=$stmt->fetchAll();
    foreach($rows as &$r) $r['fotos']=$r['fotos']?json_decode($r['fotos'],true):[];
    ok($rows);
}
// ── UPLOAD FOTO INVENTARIO ────────────────────────────────
// Enviar como multipart/form-data com ?action=upload_foto_inventario
// Campos: inventario_id (int), foto (file)
elseif($action==='upload_foto_inventario' && $method==='POST'){
    $u=require_auth(['gestor','operacional']);
    $invId=(int)($_POST['inventario_id']??0);
    if(!$invId) err('inventario_id obrigatório');
    if(empty($_FILES['foto'])) err('Campo foto obrigatório');
    // Valida inventário + permissão operacional
    $stmtI=db()->prepare(
        'SELECT ai.id,uo.nome AS unidade_nome
         FROM ativos_inventarios ai
         JOIN ativos a ON a.id=ai.ativo_id
         LEFT JOIN unidades_operacionais uo ON uo.id=a.unidade_id
         WHERE ai.id=?'
    );
    $stmtI->execute([$invId]); $inv=$stmtI->fetch();
    if(!$inv) err('Inventário não encontrado',404);
    if($u['role']==='operacional' && $inv['unidade_nome']!==$u['unidade']) err('Acesso negado',403);
    // Valida arquivo
    $file=$_FILES['foto'];
    if($file['error']!==UPLOAD_ERR_OK) err('Erro no upload — código '.$file['error']);
    if($file['size']>10*1024*1024) err('Arquivo muito grande — máximo 10 MB');
    $mime=mime_content_type($file['tmp_name']);
    $exts=['image/jpeg'=>'jpg','image/png'=>'png','image/webp'=>'webp'];
    if(!isset($exts[$mime])) err('Formato inválido — envie JPG, PNG ou WEBP');
    // Salva em /uploads/inventarios/{inventario_id}/
    $dir='/var/www/gvc-drc/uploads/inventarios/'.$invId;
    if(!is_dir($dir)) mkdir($dir,0755,true);
    $nome=uniqid('foto_').'.'.$exts[$mime];
    if(!move_uploaded_file($file['tmp_name'],$dir.'/'.$nome)) err('Falha ao salvar arquivo no servidor');
    $caminho='/uploads/inventarios/'.$invId.'/'.$nome;
    db()->prepare(
        'INSERT INTO ativos_inventario_fotos (inventario_id,nome_arquivo,caminho,tamanho_bytes) VALUES (?,?,?,?)'
    )->execute([$invId,$nome,$caminho,$file['size']]);
    ok(['id'=>(int)db()->lastInsertId(),'url'=>'https://api.drc-gvc.tech'.$caminho]);
}
// ── UPLOAD LOGOMARCA ATIVO ────────────────────────────────
// Enviar como multipart/form-data com ?action=upload_logomarca_ativo
// Campos: ativo_id (int), logomarca (file)
elseif($action==='upload_logomarca_ativo' && $method==='POST'){
    require_auth(['gestor']);
    $ativoId=(int)($_POST['ativo_id']??0);
    if(!$ativoId) err('ativo_id obrigatório');
    if(empty($_FILES['logomarca'])) err('Campo logomarca obrigatório');
    $stmt=db()->prepare('SELECT id FROM ativos WHERE id=?'); $stmt->execute([$ativoId]);
    if(!$stmt->fetch()) err('Ativo não encontrado',404);
    // Valida arquivo
    $file=$_FILES['logomarca'];
    if($file['error']!==UPLOAD_ERR_OK) err('Erro no upload — código '.$file['error']);
    if($file['size']>5*1024*1024) err('Arquivo muito grande — máximo 5 MB');
    $mime=mime_content_type($file['tmp_name']);
    $exts=['image/jpeg'=>'jpg','image/png'=>'png','image/webp'=>'webp'];
    if(!isset($exts[$mime])) err('Formato inválido — envie JPG, PNG ou WEBP');
    // Salva em /uploads/ativos/{ativo_id}/plotagem.ext
    $dir='/var/www/gvc-drc/uploads/ativos/'.$ativoId;
    if(!is_dir($dir)) mkdir($dir,0755,true);
    $nome='plotagem.'.$exts[$mime];
    if(!move_uploaded_file($file['tmp_name'],$dir.'/'.$nome)) err('Falha ao salvar arquivo no servidor');
    $caminho='/uploads/ativos/'.$ativoId.'/'.$nome;
    db()->prepare('UPDATE ativos SET logomarca_url=? WHERE id=?')->execute([$caminho,$ativoId]);
    ok(['url'=>'https://api.drc-gvc.tech'.$caminho]);
}
else { err('Ação desconhecida: '.htmlspecialchars($action),404); }
