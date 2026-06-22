-- ============================================================
-- Migration: migration_ativos_v3.1.0.sql
-- Versão: 3.1.0
-- Data: 2026-06-22
-- Autor: Milton / Grupo GVC
-- Descrição: Módulo de Controle de Ativos Logísticos
--   Cobre: caminhões, caixas roll-on e poliguindaste
--   Inclui: unidades operacionais, inventários com foto
--            e histórico de transferências entre unidades
-- Depende de: schema gvc_drc existente (api.php v3.0)
-- Resultado: base para api.php v3.1.0
-- Etapa: 1 de 6
-- ============================================================
-- CHANGELOG
--   3.1.0 - 2026-06-22 - feat: módulo completo de ativos logísticos
--                        5 tabelas: unidades_operacionais, ativos,
--                        ativos_transferencias, ativos_inventarios,
--                        ativos_inventario_fotos
-- ============================================================
-- DEPLOY
--   1. Backup (OBRIGATÓRIO antes de aplicar):
--      mysqldump -u gvc_user -p'Gvc@2025!DRC' gvc_drc > backup_pre_ativos_$(date +%Y%m%d).sql
--
--   2. Aplicar migration:
--      mysql -u gvc_user -p'Gvc@2025!DRC' gvc_drc < migration_ativos_v3.1.0.sql
--
--   3. Conferir resultado com as queries de verificação no final do arquivo
-- ============================================================
-- ROLLBACK (executar na ordem inversa caso necessário)
--   DROP TABLE IF EXISTS ativos_inventario_fotos;
--   DROP TABLE IF EXISTS ativos_inventarios;
--   DROP TABLE IF EXISTS ativos_transferencias;
--   DROP TABLE IF EXISTS ativos;
--   DROP TABLE IF EXISTS unidades_operacionais;
-- ============================================================

USE gvc_drc;

-- ============================================================
-- TABELA 1: unidades_operacionais
-- Registro estruturado das 10 unidades operacionais do Grupo GVC.
-- Referenciada como FK em ativos, ativos_transferencias e
-- ativos_inventarios.
-- ============================================================

CREATE TABLE IF NOT EXISTS unidades_operacionais (
    id          INT          NOT NULL AUTO_INCREMENT,
    nome        VARCHAR(200) NOT NULL,
    codigo      VARCHAR(20)  NOT NULL                    COMMENT 'Código curto único (ex: ULT-SSA, RET-SF)',
    empresa     VARCHAR(100) NULL,
    municipio   VARCHAR(100) NULL,
    uf          CHAR(2)      NOT NULL DEFAULT 'BA',
    ativo       TINYINT(1)   NOT NULL DEFAULT 1,
    created_at  TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (id),
    UNIQUE KEY uq_unidades_codigo (codigo)
) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_unicode_ci
  COMMENT='Unidades operacionais do Grupo GVC';

-- 10 unidades operacionais confirmadas
-- municipio NULL em RETEC Oeste BJL, CVR Oeste e CVR São Francisco — a confirmar
-- Após confirmar, atualizar com:
--   UPDATE unidades_operacionais SET municipio = 'NOME_MUNICIPIO' WHERE codigo = 'CODIGO';

INSERT INTO unidades_operacionais (nome, codigo, empresa, municipio, uf) VALUES
    ('ULTRA Salvador',        'ULT-SSA',   'Ultra Ambiental',   'Salvador',     'BA'),
    ('RETEC Simões Filho',    'RET-SF',    'RETEC',             'Simões Filho', 'BA'),
    ('RETEC Juazeiro',        'RET-JUA',   'RETEC',             'Juazeiro',     'BA'),
    ('RETEC Oeste Barreiras', 'RET-O-BAR', 'RETEC Oeste',       'Barreiras',    'BA'),
    ('RETEC Oeste Guanambi',  'RET-O-GNA', 'RETEC Oeste',       'Guanambi',     'BA'),
    ('RETEC Oeste BJL',       'RET-O-BJL', 'RETEC Oeste',       NULL,           'BA'),
    ('CVR Oeste',             'CVR-O',     'CVR Oeste',         NULL,           'BA'),
    ('CVR São Francisco',     'CVR-SF',    'CVR São Francisco',  NULL,           'BA'),
    ('CVR Alto Sertão',       'CVR-AS',    'CVR Alto Sertão',   'Caetité',      'BA'),
    ('EVE Ambiental',         'EVE-PE',    'EVE Ambiental',     'Paulista',     'PE');


-- ============================================================
-- TABELA 2: ativos
-- Registro mestre de todos os ativos logísticos.
-- Código auto-gerado pela API no formato:
--   Caminhão      → CAM-0001, CAM-0002 …
--   Roll-on       → ROL-0001, ROL-0002 …
--   Poliguindaste → POL-0001, POL-0002 …
-- ============================================================

CREATE TABLE IF NOT EXISTS ativos (
    id                          INT              NOT NULL AUTO_INCREMENT,

    -- ── Identificação geral ───────────────────────────────
    codigo                      VARCHAR(50)      NOT NULL               COMMENT 'Gerado pela API: CAM-0001, ROL-0001, POL-0001',
    tipo                        ENUM(
                                    'caminhao',
                                    'roll_on',
                                    'poliguindaste'
                                )                NOT NULL,
    descricao                   VARCHAR(255)     NOT NULL,
    numero_interno              VARCHAR(50)      NULL                   COMMENT 'Plaqueta/numeração física GVC pintada no ativo (ex: V-42)',

    -- ── Documentação veicular — somente caminhão ─────────
    placa                       VARCHAR(20)      NULL,
    chassi                      VARCHAR(100)     NULL,
    renavam                     VARCHAR(20)      NULL,

    -- ── Identificação do produto ──────────────────────────
    marca                       VARCHAR(100)     NULL,
    modelo                      VARCHAR(100)     NULL,
    cor                         VARCHAR(50)      NULL,
    tipo_carroceria             VARCHAR(100)     NULL                   COMMENT 'Baú, sucção, basculante, tanque, poliguindaste, compactador…',
    ano_fabricacao              YEAR             NULL,
    ano_modelo                  YEAR             NULL,

    -- ── Motorização — somente caminhão ───────────────────
    tipo_combustivel            ENUM(
                                    'gasolina',
                                    'etanol',
                                    'flex',
                                    'diesel',
                                    'diesel_s10',
                                    'gnv',
                                    'eletrico',
                                    'hibrido'
                                )                NULL,
    num_tanques_combustivel     TINYINT UNSIGNED NULL                   COMMENT 'Quantidade de tanques de combustível do veículo',
    tanques_combustivel_litros  JSON             NULL                   COMMENT 'Capacidade por tanque em litros. Ex: [600, 600] para dois tanques de 600 L cada',

    -- ── Pesos regulatórios DENATRAN/CRLV — somente caminhão
    pbt_kg                      DECIMAL(10,2)    NULL                   COMMENT 'Peso Bruto Total (kg)',
    cmt_kg                      DECIMAL(10,2)    NULL                   COMMENT 'Capacidade Máxima de Tração (kg)',

    -- ── Capacidades de carga ──────────────────────────────
    capacidade_carga_kg         DECIMAL(10,2)    NULL                   COMMENT 'Carga útil em kg (caminhões de carga)',
    capacidade_m3               DECIMAL(10,2)    NULL                   COMMENT 'Capacidade volumétrica em m³ (caminhões de sucção/tanque)',
    capacidade_bombonas         SMALLINT UNSIGNED NULL                  COMMENT 'Nº de bombonas suportadas — implemento baú',

    -- ── Dimensões do veículo ou caixa (metros) ───────────
    comprimento                 DECIMAL(6,2)     NULL,
    largura                     DECIMAL(6,2)     NULL,
    altura                      DECIMAL(6,2)     NULL,

    -- ── Dimensões do implemento — somente caminhão (metros)
    impl_comprimento            DECIMAL(6,2)     NULL,
    impl_largura                DECIMAL(6,2)     NULL,
    impl_altura                 DECIMAL(6,2)     NULL,

    -- ── Específico de containers (roll_on / poliguindaste) 
    numero_serie                VARCHAR(100)     NULL,
    fabricante                  VARCHAR(100)     NULL,
    volume_m3                   DECIMAL(10,2)    NULL                   COMMENT 'Volume interno do container em m³',

    -- ── Propriedade ───────────────────────────────────────
    ownership                   ENUM(
                                    'proprio',
                                    'alugado'
                                )                NOT NULL DEFAULT 'proprio',
    fornecedor_aluguel          VARCHAR(255)     NULL,
    contrato_aluguel            VARCHAR(100)     NULL,
    vencimento_aluguel          DATE             NULL,

    -- ── Localização e estado ──────────────────────────────
    unidade_id                  INT              NULL,
    status                      ENUM(
                                    'ativo',
                                    'manutencao',
                                    'baixado'
                                )                NOT NULL DEFAULT 'ativo',

    -- ── Identidade visual / plotagem ──────────────────────
    logomarca_url               VARCHAR(500)     NULL                   COMMENT 'Caminho relativo do arquivo em /uploads/ativos/{id}/plotagem.jpg',

    -- ── Controle financeiro e administrativo ─────────────
    valor_estimado              DECIMAL(12,2)    NULL,
    data_aquisicao              DATE             NULL,
    observacoes                 TEXT             NULL,

    -- ── Timestamps ────────────────────────────────────────
    created_at                  TIMESTAMP        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at                  TIMESTAMP        NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    PRIMARY KEY (id),
    UNIQUE KEY  uq_ativos_codigo    (codigo),
    KEY         idx_ativos_tipo     (tipo),
    KEY         idx_ativos_status   (status),
    KEY         idx_ativos_unidade  (unidade_id),
    KEY         idx_ativos_own      (ownership),
    KEY         idx_ativos_placa    (placa),

    CONSTRAINT fk_ativos_unidade
        FOREIGN KEY (unidade_id)
        REFERENCES unidades_operacionais(id)
        ON DELETE SET NULL

) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_unicode_ci
  COMMENT='Registro mestre de ativos logísticos — caminhões, roll-on e poliguindaste';


-- ============================================================
-- TABELA 3: ativos_transferencias
-- Histórico imutável de transferências entre unidades.
-- Os campos *_nome preservam snapshot do nome da unidade no
-- momento da transferência para fins de auditoria.
-- ============================================================

CREATE TABLE IF NOT EXISTS ativos_transferencias (
    id                      INT          NOT NULL AUTO_INCREMENT,
    ativo_id                INT          NOT NULL,
    unidade_origem_id       INT          NULL,
    unidade_destino_id      INT          NULL,
    unidade_origem_nome     VARCHAR(200) NULL                   COMMENT 'Snapshot do nome da unidade de origem na data da transferência',
    unidade_destino_nome    VARCHAR(200) NULL                   COMMENT 'Snapshot do nome da unidade de destino na data da transferência',
    data_transferencia      DATETIME     NOT NULL,
    motivo                  TEXT         NULL,
    usuario_id              INT          NOT NULL,
    usuario_nome            VARCHAR(200) NULL,
    observacoes             TEXT         NULL,
    created_at              TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (id),
    KEY idx_transf_ativo    (ativo_id),
    KEY idx_transf_destino  (unidade_destino_id),
    KEY idx_transf_data     (data_transferencia),

    CONSTRAINT fk_transf_ativo
        FOREIGN KEY (ativo_id)
        REFERENCES ativos(id)
        ON DELETE CASCADE,

    CONSTRAINT fk_transf_origem
        FOREIGN KEY (unidade_origem_id)
        REFERENCES unidades_operacionais(id)
        ON DELETE SET NULL,

    CONSTRAINT fk_transf_destino_u
        FOREIGN KEY (unidade_destino_id)
        REFERENCES unidades_operacionais(id)
        ON DELETE SET NULL

) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_unicode_ci
  COMMENT='Histórico de transferências de ativos entre unidades operacionais';


-- ============================================================
-- TABELA 4: ativos_inventarios
-- Inspeções periódicas de conservação dos ativos.
-- Fotos associadas ficam em ativos_inventario_fotos.
-- O campo unidade_nome preserva snapshot para auditoria.
-- ============================================================

CREATE TABLE IF NOT EXISTS ativos_inventarios (
    id              INT          NOT NULL AUTO_INCREMENT,
    ativo_id        INT          NOT NULL,
    unidade_id      INT          NULL,
    unidade_nome    VARCHAR(200) NULL                   COMMENT 'Snapshot do nome da unidade na data do inventário',
    data_inventario DATETIME     NOT NULL,
    usuario_id      INT          NOT NULL,
    usuario_nome    VARCHAR(200) NULL,
    condicao        ENUM(
                        'otimo',
                        'bom',
                        'regular',
                        'ruim',
                        'inoperante'
                    )            NOT NULL,
    observacoes     TEXT         NULL,
    created_at      TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (id),
    KEY idx_inv_ativo    (ativo_id),
    KEY idx_inv_unidade  (unidade_id),
    KEY idx_inv_condicao (condicao),
    KEY idx_inv_data     (data_inventario),

    CONSTRAINT fk_inv_ativo
        FOREIGN KEY (ativo_id)
        REFERENCES ativos(id)
        ON DELETE CASCADE,

    CONSTRAINT fk_inv_unidade
        FOREIGN KEY (unidade_id)
        REFERENCES unidades_operacionais(id)
        ON DELETE SET NULL

) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_unicode_ci
  COMMENT='Inspeções periódicas de conservação dos ativos logísticos';


-- ============================================================
-- TABELA 5: ativos_inventario_fotos
-- Fotos anexadas a cada inventário.
-- Arquivos salvos em: /uploads/inventarios/{inventario_id}/
-- Servidos em:        https://api.drc-gvc.tech/uploads/inventarios/{id}/arquivo.jpg
-- ON DELETE CASCADE — ao excluir o inventário, as fotos são
-- removidas automaticamente da tabela (arquivo físico deve ser
-- removido separadamente pelo endpoint da API).
-- ============================================================

CREATE TABLE IF NOT EXISTS ativos_inventario_fotos (
    id              INT          NOT NULL AUTO_INCREMENT,
    inventario_id   INT          NOT NULL,
    nome_arquivo    VARCHAR(255) NOT NULL,
    caminho         VARCHAR(500) NOT NULL                   COMMENT 'Caminho relativo a partir da raiz da API',
    tamanho_bytes   INT UNSIGNED NULL,
    created_at      TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (id),
    KEY idx_fotos_inv (inventario_id),

    CONSTRAINT fk_fotos_inv
        FOREIGN KEY (inventario_id)
        REFERENCES ativos_inventarios(id)
        ON DELETE CASCADE

) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_unicode_ci
  COMMENT='Fotos das inspeções de conservação dos ativos';


-- ============================================================
-- VERIFICAÇÃO — executar após o migration para confirmar
-- ============================================================

-- 1. Confirma as 5 tabelas criadas
SELECT
    table_name          AS tabela,
    table_rows          AS linhas_aprox,
    table_comment       AS descricao
FROM information_schema.tables
WHERE table_schema = 'gvc_drc'
  AND table_name IN (
      'unidades_operacionais',
      'ativos',
      'ativos_transferencias',
      'ativos_inventarios',
      'ativos_inventario_fotos'
  )
ORDER BY table_name;

-- 2. Confirma as 10 unidades operacionais inseridas
SELECT id, codigo, nome, empresa, municipio, uf, ativo
FROM unidades_operacionais
ORDER BY id;

-- 3. Confirma colunas da tabela ativos (deve retornar 47 colunas)
SELECT COUNT(*) AS total_colunas
FROM information_schema.columns
WHERE table_schema = 'gvc_drc'
  AND table_name = 'ativos';
