table ip filter {
        map whalewall-container-addrs {
                type ipv4_addr : verdict
                elements = { 172.16.96.2 : jump whalewall-app-miniflux_db-1-9dc62ada7228, 172.16.96.3 : jump whalewall-app-miniflux-1-7e12fbbff0bb }
        }

        chain DOCKER {
                iifname != "br-12da8a9b679d" oifname "br-12da8a9b679d" meta l4proto tcp ip daddr 172.21.0.2 tcp dport 6001 counter packets 0 bytes 0 accept
                iifname != "br-12da8a9b679d" oifname "br-12da8a9b679d" meta l4proto tcp ip daddr 172.21.0.4 tcp dport 80 counter packets 0 bytes 0 accept
                iifname != "br-12da8a9b679d" oifname "br-12da8a9b679d" meta l4proto tcp ip daddr 172.21.0.3 tcp dport 80 counter packets 0 bytes 0 accept
                iifname != "br-12da8a9b679d" oifname "br-12da8a9b679d" meta l4proto tcp ip daddr 172.21.0.3 tcp dport 443 counter packets 0 bytes 0 accept
                iifname != "br-12da8a9b679d" oifname "br-12da8a9b679d" meta l4proto tcp ip daddr 172.21.0.3 tcp dport 8080 counter packets 0 bytes 0 accept
                iifname != "br-65db3a569fb8" oifname "br-65db3a569fb8" meta l4proto tcp ip daddr 172.16.96.3 tcp dport 8080 counter packets 0 bytes 0 accept
        }

        chain DOCKER-ISOLATION-STAGE-1 {
                ;; Summary: Drop if bound for a different Docker network
                iifname "docker0" oifname != "docker0" counter packets 2 bytes 128 jump DOCKER-ISOLATION-STAGE-2
                iifname "docker_gwbridge" oifname != "docker_gwbridge" counter packets 0 bytes 0 jump DOCKER-ISOLATION-STAGE-2
                iifname "br-f8ea66866f31" oifname != "br-f8ea66866f31" counter packets 0 bytes 0 jump DOCKER-ISOLATION-STAGE-2
                iifname "br-d3041f60d0a3" oifname != "br-d3041f60d0a3" counter packets 0 bytes 0 jump DOCKER-ISOLATION-STAGE-2
                iifname "br-91e50e8d0579" oifname != "br-91e50e8d0579" counter packets 0 bytes 0 jump DOCKER-ISOLATION-STAGE-2
                iifname "br-65db3a569fb8" oifname != "br-65db3a569fb8" counter packets 0 bytes 0 jump DOCKER-ISOLATION-STAGE-2
                iifname "br-12da8a9b679d" oifname != "br-12da8a9b679d" counter packets 6425 bytes 504328 jump DOCKER-ISOLATION-STAGE-2
                iifname "br-fcd51a186602" oifname != "br-fcd51a186602" counter packets 0 bytes 0 jump DOCKER-ISOLATION-STAGE-2
                iifname "br-c8856ae51231" oifname != "br-c8856ae51231" counter packets 0 bytes 0 jump DOCKER-ISOLATION-STAGE-2
                iifname "br-6be0ddea13a1" oifname != "br-6be0ddea13a1" counter packets 0 bytes 0 jump DOCKER-ISOLATION-STAGE-2
                counter packets 8483443 bytes 1526462070 return
        }

        chain DOCKER-ISOLATION-STAGE-2 {
                oifname "docker0" counter packets 0 bytes 0 drop
                oifname "docker_gwbridge" counter packets 0 bytes 0 drop
                oifname "br-f8ea66866f31" counter packets 0 bytes 0 drop
                oifname "br-d3041f60d0a3" counter packets 0 bytes 0 drop
                oifname "br-91e50e8d0579" counter packets 0 bytes 0 drop
                oifname "br-65db3a569fb8" counter packets 0 bytes 0 drop
                oifname "br-12da8a9b679d" counter packets 0 bytes 0 drop
                oifname "br-fcd51a186602" counter packets 0 bytes 0 drop
                oifname "br-c8856ae51231" counter packets 0 bytes 0 drop
                oifname "br-6be0ddea13a1" counter packets 0 bytes 0 drop
                counter packets 6427 bytes 504456 return
        }

        chain FORWARD {
                type filter hook forward priority filter; policy drop;
                counter packets 8485695 bytes 1526626146 jump DOCKER-USER
                counter packets 8483443 bytes 1526462070 jump DOCKER-ISOLATION-STAGE-1

                oifname "docker0" ct state related,established counter packets 2 bytes 209 accept
                oifname "docker0" counter packets 0 bytes 0 jump DOCKER
                iifname "docker0" oifname != "docker0" counter packets 2 bytes 128 accept
                iifname "docker0" oifname "docker0" counter packets 0 bytes 0 accept

                oifname "docker_gwbridge" ct state related,established counter packets 0 bytes 0 accept
                oifname "docker_gwbridge" counter packets 0 bytes 0 jump DOCKER
                iifname "docker_gwbridge" oifname != "docker_gwbridge" counter packets 0 bytes 0 accept

                oifname "br-f8ea66866f31" ct state related,established counter packets 0 bytes 0 accept
                oifname "br-f8ea66866f31" counter packets 0 bytes 0 jump DOCKER
                iifname "br-f8ea66866f31" oifname != "br-f8ea66866f31" counter packets 0 bytes 0 accept
                iifname "br-f8ea66866f31" oifname "br-f8ea66866f31" counter packets 0 bytes 0 accept

                oifname "br-d3041f60d0a3" ct state related,established counter packets 0 bytes 0 accept
                oifname "br-d3041f60d0a3" counter packets 0 bytes 0 jump DOCKER
                iifname "br-d3041f60d0a3" oifname != "br-d3041f60d0a3" counter packets 0 bytes 0 accept
                iifname "br-d3041f60d0a3" oifname "br-d3041f60d0a3" counter packets 0 bytes 0 accept
                oifname "br-91e50e8d0579" ct state related,established counter packets 0 bytes 0 accept
                oifname "br-91e50e8d0579" counter packets 0 bytes 0 jump DOCKER
                iifname "br-91e50e8d0579" oifname != "br-91e50e8d0579" counter packets 0 bytes 0 accept
                iifname "br-91e50e8d0579" oifname "br-91e50e8d0579" counter packets 0 bytes 0 accept
                oifname "br-65db3a569fb8" ct state related,established counter packets 0 bytes 0 accept
                oifname "br-65db3a569fb8" counter packets 0 bytes 0 jump DOCKER
                iifname "br-65db3a569fb8" oifname != "br-65db3a569fb8" counter packets 0 bytes 0 accept
                iifname "br-65db3a569fb8" oifname "br-65db3a569fb8" counter packets 0 bytes 0 accept
                oifname "br-12da8a9b679d" ct state related,established counter packets 7360745 bytes 1253207181 accept
                oifname "br-12da8a9b679d" counter packets 1116269 bytes 272750224 jump DOCKER
                iifname "br-12da8a9b679d" oifname != "br-12da8a9b679d" counter packets 6425 bytes 504328 accept
                iifname "br-12da8a9b679d" oifname "br-12da8a9b679d" counter packets 1116269 bytes 272750224 accept
                oifname "br-fcd51a186602" ct state related,established counter packets 0 bytes 0 accept
                oifname "br-fcd51a186602" counter packets 0 bytes 0 jump DOCKER
                iifname "br-fcd51a186602" oifname != "br-fcd51a186602" counter packets 0 bytes 0 accept
                iifname "br-fcd51a186602" oifname "br-fcd51a186602" counter packets 0 bytes 0 accept
                oifname "br-c8856ae51231" ct state related,established counter packets 0 bytes 0 accept
                oifname "br-c8856ae51231" counter packets 0 bytes 0 jump DOCKER
                iifname "br-c8856ae51231" oifname != "br-c8856ae51231" counter packets 0 bytes 0 accept
                iifname "br-c8856ae51231" oifname "br-c8856ae51231" counter packets 0 bytes 0 accept
                oifname "br-6be0ddea13a1" ct state related,established counter packets 0 bytes 0 accept
                oifname "br-6be0ddea13a1" counter packets 0 bytes 0 jump DOCKER
                iifname "br-6be0ddea13a1" oifname != "br-6be0ddea13a1" counter packets 0 bytes 0 accept
                iifname "br-6be0ddea13a1" oifname "br-6be0ddea13a1" counter packets 0 bytes 0 accept
                iifname "docker_gwbridge" oifname "docker_gwbridge" counter packets 0 bytes 0 drop
        }

        chain DOCKER-USER {
                counter packets 8481172 bytes 1525747389 jump whalewall
                counter packets 8483443 bytes 1526462070 return
        }

        chain whalewall {
                ip saddr vmap @whalewall-container-addrs
                ip daddr vmap @whalewall-container-addrs
        }

        chain INPUT {
                type filter hook input priority filter; policy accept;
                counter packets 603439 bytes 135380932 jump whalewall
        }

        chain OUTPUT {
                type filter hook output priority filter; policy accept;
                counter packets 181767 bytes 183318444 jump whalewall
        }

        chain whalewall-app-miniflux_db-1-9dc62ada7228 {
                ip saddr 172.16.96.2 ip daddr 172.16.96.3 tcp sport 5432 ct state established,related counter packets 1048 bytes 81654 accept
                counter packets 0 bytes 0 log prefix "whalewall-app-miniflux_db-1-9dc62ada7228 drop: " level info drop
        }

        chain whalewall-app-miniflux-1-7e12fbbff0bb {
                ip saddr 172.16.96.1 ip daddr 172.16.96.3 tcp dport 8080 ct state established,related,new counter packets 0 bytes 0 accept
                ip saddr 172.16.96.3 ip daddr 172.16.96.1 tcp sport 8080 ct state established,related counter packets 0 bytes 0 accept
                ip saddr 192.168.1.0-192.168.1.255 ip daddr 172.16.96.3 tcp dport 8080 ct state established,related,new counter packets 0 bytes 0 accept
                ip saddr 172.16.96.3 ip daddr 192.168.1.0-192.168.1.255 tcp sport 8080 ct state established,related counter packets 0 bytes 0 accept
                ip saddr 172.16.96.3 ip daddr 172.16.96.2 tcp dport 5432 ct state established,related,new counter packets 1203 bytes 82362 accept
                ip saddr 172.16.96.3 udp dport 53 ct state new counter packets 0 bytes 0 log prefix "whalewall-app-miniflux-1-7e12fbbff0bb dns: " level info accept
                ip saddr 172.16.96.3 udp dport 53 ct state established,related counter packets 0 bytes 0 accept
                ip daddr 172.16.96.3 udp sport 53 ct state established,related counter packets 0 bytes 0 accept
                ip saddr 172.16.96.3 tcp dport 443 ct state new counter packets 0 bytes 0 log prefix "whalewall-app-miniflux-1-7e12fbbff0bb https: " level info accept
                ip saddr 172.16.96.3 tcp dport 443 ct state established,related counter packets 0 bytes 0 accept
                ip daddr 172.16.96.3 tcp sport 443 ct state established,related counter packets 0 bytes 0 accept
                counter packets 1 bytes 60 log prefix "whalewall-app-miniflux-1-7e12fbbff0bb drop: " level info drop
        }
}
table ip nat {
        chain DOCKER {
                iifname "docker0" counter packets 0 bytes 0 return
                iifname "docker_gwbridge" counter packets 0 bytes 0 return
                iifname "br-f8ea66866f31" counter packets 0 bytes 0 return
                iifname "br-d3041f60d0a3" counter packets 0 bytes 0 return
                iifname "br-91e50e8d0579" counter packets 0 bytes 0 return
                iifname "br-65db3a569fb8" counter packets 0 bytes 0 return
                iifname "br-12da8a9b679d" counter packets 7610 bytes 456600 return
                iifname "br-fcd51a186602" counter packets 0 bytes 0 return
                iifname "br-c8856ae51231" counter packets 0 bytes 0 return
                iifname "br-6be0ddea13a1" counter packets 0 bytes 0 return
                iifname != "br-12da8a9b679d" meta l4proto tcp tcp dport 6001 counter packets 0 bytes 0 dnat to 172.21.0.2:6001
                iifname != "br-12da8a9b679d" meta l4proto tcp tcp dport 8000 counter packets 0 bytes 0 dnat to 172.21.0.4:80
                iifname != "br-12da8a9b679d" meta l4proto tcp tcp dport 80 counter packets 0 bytes 0 dnat to 172.21.0.3:80
                iifname != "br-12da8a9b679d" meta l4proto tcp tcp dport 443 counter packets 0 bytes 0 dnat to 172.21.0.3:443
                iifname != "br-12da8a9b679d" meta l4proto tcp tcp dport 8080 counter packets 0 bytes 0 dnat to 172.21.0.3:8080
                iifname != "br-65db3a569fb8" meta l4proto tcp tcp dport 8090 counter packets 0 bytes 0 dnat to 172.16.96.3:8080
        }

        chain POSTROUTING {
                type nat hook postrouting priority srcnat; policy accept;
                oifname != "docker0" ip saddr 172.16.64.0/20 counter packets 2 bytes 128 masquerade 
                oifname != "docker_gwbridge" ip saddr 172.16.80.0/20 counter packets 0 bytes 0 masquerade 
                oifname != "br-f8ea66866f31" ip saddr 172.16.128.0/20 counter packets 0 bytes 0 masquerade 
                oifname != "br-d3041f60d0a3" ip saddr 172.16.16.0/20 counter packets 0 bytes 0 masquerade 
                oifname != "br-91e50e8d0579" ip saddr 172.18.0.0/16 counter packets 0 bytes 0 masquerade 
                oifname != "br-65db3a569fb8" ip saddr 172.16.96.0/20 counter packets 0 bytes 0 masquerade 
                oifname != "br-12da8a9b679d" ip saddr 172.21.0.0/16 counter packets 376 bytes 23742 masquerade 
                oifname != "br-fcd51a186602" ip saddr 172.16.0.0/20 counter packets 0 bytes 0 masquerade 
                oifname != "br-c8856ae51231" ip saddr 172.16.48.0/20 counter packets 0 bytes 0 masquerade 
                oifname != "br-6be0ddea13a1" ip saddr 172.16.32.0/20 counter packets 0 bytes 0 masquerade 
                meta l4proto tcp ip saddr 172.21.0.2 ip daddr 172.21.0.2 tcp dport 6001 counter packets 0 bytes 0 masquerade 
                meta l4proto tcp ip saddr 172.21.0.4 ip daddr 172.21.0.4 tcp dport 80 counter packets 0 bytes 0 masquerade 
                meta l4proto tcp ip saddr 172.21.0.3 ip daddr 172.21.0.3 tcp dport 80 counter packets 0 bytes 0 masquerade 
                meta l4proto tcp ip saddr 172.21.0.3 ip daddr 172.21.0.3 tcp dport 443 counter packets 0 bytes 0 masquerade 
                meta l4proto tcp ip saddr 172.21.0.3 ip daddr 172.21.0.3 tcp dport 8080 counter packets 0 bytes 0 masquerade 
                meta l4proto tcp ip saddr 172.16.96.3 ip daddr 172.16.96.3 tcp dport 8080 counter packets 0 bytes 0 masquerade 
        }

        chain PREROUTING {
                type nat hook prerouting priority dstnat; policy accept;
                fib daddr type local counter packets 7652 bytes 460008 jump DOCKER
        }

        chain OUTPUT {
                type nat hook output priority -100; policy accept;
                ip daddr != 127.0.0.0/8 fib daddr type local counter packets 0 bytes 0 jump DOCKER
        }
}
table ip6 filter {
        chain DOCKER {
        }

        chain DOCKER-ISOLATION-STAGE-1 {
                iifname "docker0" oifname != "docker0" counter packets 0 bytes 0 jump DOCKER-ISOLATION-STAGE-2
                iifname "docker_gwbridge" oifname != "docker_gwbridge" counter packets 0 bytes 0 jump DOCKER-ISOLATION-STAGE-2
                iifname "br-f8ea66866f31" oifname != "br-f8ea66866f31" counter packets 0 bytes 0 jump DOCKER-ISOLATION-STAGE-2
                iifname "br-d3041f60d0a3" oifname != "br-d3041f60d0a3" counter packets 0 bytes 0 jump DOCKER-ISOLATION-STAGE-2
                iifname "br-91e50e8d0579" oifname != "br-91e50e8d0579" counter packets 0 bytes 0 jump DOCKER-ISOLATION-STAGE-2
                iifname "br-65db3a569fb8" oifname != "br-65db3a569fb8" counter packets 0 bytes 0 jump DOCKER-ISOLATION-STAGE-2
                iifname "br-12da8a9b679d" oifname != "br-12da8a9b679d" counter packets 0 bytes 0 jump DOCKER-ISOLATION-STAGE-2
                iifname "br-fcd51a186602" oifname != "br-fcd51a186602" counter packets 0 bytes 0 jump DOCKER-ISOLATION-STAGE-2
                iifname "br-c8856ae51231" oifname != "br-c8856ae51231" counter packets 0 bytes 0 jump DOCKER-ISOLATION-STAGE-2
                iifname "br-6be0ddea13a1" oifname != "br-6be0ddea13a1" counter packets 0 bytes 0 jump DOCKER-ISOLATION-STAGE-2
                counter packets 0 bytes 0 return
        }

        chain DOCKER-ISOLATION-STAGE-2 {
                oifname "docker0" counter packets 0 bytes 0 drop
                oifname "docker_gwbridge" counter packets 0 bytes 0 drop
                oifname "br-f8ea66866f31" counter packets 0 bytes 0 drop
                oifname "br-d3041f60d0a3" counter packets 0 bytes 0 drop
                oifname "br-91e50e8d0579" counter packets 0 bytes 0 drop
                oifname "br-65db3a569fb8" counter packets 0 bytes 0 drop
                oifname "br-12da8a9b679d" counter packets 0 bytes 0 drop
                oifname "br-fcd51a186602" counter packets 0 bytes 0 drop
                oifname "br-c8856ae51231" counter packets 0 bytes 0 drop
                oifname "br-6be0ddea13a1" counter packets 0 bytes 0 drop
                counter packets 0 bytes 0 return
        }

        chain FORWARD {
                type filter hook forward priority filter; policy drop;
                counter packets 0 bytes 0 jump DOCKER-USER
                counter packets 0 bytes 0 jump DOCKER-ISOLATION-STAGE-1
                oifname "br-d3041f60d0a3" ct state related,established counter packets 0 bytes 0 accept
                oifname "br-d3041f60d0a3" counter packets 0 bytes 0 jump DOCKER
                iifname "br-d3041f60d0a3" oifname != "br-d3041f60d0a3" counter packets 0 bytes 0 accept
                iifname "br-d3041f60d0a3" oifname "br-d3041f60d0a3" counter packets 0 bytes 0 accept
        }

        chain DOCKER-USER {
                counter packets 0 bytes 0 return
        }
}
table ip6 nat {
        chain DOCKER {
                iifname "br-d3041f60d0a3" counter packets 0 bytes 0 return
        }

        chain POSTROUTING {
                type nat hook postrouting priority srcnat; policy accept;
                oifname != "br-d3041f60d0a3" ip6 saddr fc00:f853:ccd:e793::/64 counter packets 0 bytes 0 masquerade  
        }

        chain PREROUTING {
                type nat hook prerouting priority dstnat; policy accept;
                fib daddr type local counter packets 0 bytes 0 jump DOCKER
        }

        chain OUTPUT {
                type nat hook output priority -100; policy accept;
                ip6 daddr != ::1 fib daddr type local counter packets 0 bytes 0 jump DOCKER
        }
}