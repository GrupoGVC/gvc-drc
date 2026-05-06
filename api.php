<?php
// ═══════════════════════════════════════════════════
// GVC DRC — API REST v3.0
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
    ok(['nome'=>$u['nome'],'role'=>$u['role'],'email'=>$u['email'],'unidade'=>$u['unidade']??'','permissions'=>ROLE_PERMISSIONS[$u['role']]??[]]);
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
    $stmt=db()->prepare('UPDATE cadastros SET dados=? WHERE tipo=?');
    foreach($cadastros as $tipo=>$lista) $stmt->execute([json_encode($lista,JSON_UNESCAPED_UNICODE),$tipo]);
    ok();
}
// ── USUARIOS ─────────────────────────────────────────────
elseif($action==='list_usuarios' && $method==='GET'){
    require_auth(['gestor']);
    ok(db()->query('SELECT id,nome,email,role,unidade,ativo,created_at FROM usuarios ORDER BY nome')->fetchAll());
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
else { err('Ação desconhecida: '.htmlspecialchars($action),404); }
