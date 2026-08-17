-- Execute separadamente em cada MySQL, ajustando usuário, origem, senha e nome da base.
-- O comparador NÃO precisa de INSERT/UPDATE/DELETE no banco Zabbix.

CREATE USER 'zbx_compare_ro'@'IP_DO_COMPARADOR' IDENTIFIED BY 'SENHA_FORTE';
GRANT SELECT ON zabbix.* TO 'zbx_compare_ro'@'IP_DO_COMPARADOR';
FLUSH PRIVILEGES;
