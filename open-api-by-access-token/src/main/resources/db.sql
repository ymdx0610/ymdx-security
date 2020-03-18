CREATE TABLE `app_info` (
  `id` bigint(11) NOT NULL AUTO_INCREMENT COMMENT '记录ID',
  `app_name` varchar(255) NOT NULL COMMENT '机构名称',
  `app_id` varchar(255) NOT NULL COMMENT '应用ID',
  `app_secret` varchar(255) NOT NULL COMMENT '应用密钥（可更改）',
  `access_token` varchar(255) NOT NULL DEFAULT '' COMMENT '最新的许可令牌',
  `status` int(1) NOT NULL DEFAULT '0' COMMENT '是否可用 （是否对某个机构开放）：0 正常 1 禁用',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8
