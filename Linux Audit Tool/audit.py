import os
import subprocess
import sys
import json
import pwd
import grp
import stat
import socket
import re
from datetime import datetime
from pathlib import Path


class SecurityAuditor:
    def __init__(self):
        self.results = {
            'timestamp': datetime.now().isoformat(),
            'hostname': socket.gethostname(),
            'checks': {},
            'summary': {'passed': 0, 'failed': 0, 'warnings': 0}
        }
        
    def run_command(self, cmd, shell=False):
        """Execute system command and return output"""
        try:
            if shell:
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
            else:
                result = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=30)
            return result.returncode, result.stdout.strip(), result.stderr.strip()
        except subprocess.TimeoutExpired:
            return -1, "", "Command timeout"
        except Exception as e:
            return -1, "", str(e)

    def check_file_permissions(self, filepath, expected_perms, description):
        """Check file permissions"""
        try:
            if not os.path.exists(filepath):
                return {'status': 'FAIL', 'message': f"File {filepath} does not exist"}
            
            file_stat = os.stat(filepath)
            actual_perms = oct(file_stat.st_mode)[-3:]
            
            if actual_perms == expected_perms:
                return {'status': 'PASS', 'message': f"{description}: Correct permissions ({expected_perms})"}
            else:
                return {'status': 'FAIL', 'message': f"{description}: Incorrect permissions. Expected {expected_perms}, got {actual_perms}"}
        except Exception as e:
            return {'status': 'ERROR', 'message': f"Error checking {filepath}: {str(e)}"}

    def audit_user_accounts(self):
        """Audit user account security"""
        checks = {}
        
        # Check for users with empty passwords
        ret_code, output, _ = self.run_command("awk -F: '($2 == \"\") {print $1}' /etc/shadow", shell=True)
        if ret_code == 0:
            empty_pass_users = output.strip().split('\n') if output else []
            if empty_pass_users and empty_pass_users[0]:
                checks['empty_passwords'] = {
                    'status': 'FAIL',
                    'message': f"Users with empty passwords: {', '.join(empty_pass_users)}"
                }
            else:
                checks['empty_passwords'] = {
                    'status': 'PASS',
                    'message': "No users with empty passwords found"
                }
        
        # Check for UID 0 accounts (should only be root)
        ret_code, output, _ = self.run_command("awk -F: '($3 == 0) {print $1}' /etc/passwd", shell=True)
        if ret_code == 0:
            uid0_users = output.strip().split('\n') if output else []
            if len(uid0_users) > 1 or (len(uid0_users) == 1 and uid0_users[0] != 'root'):
                checks['uid_zero_accounts'] = {
                    'status': 'FAIL',
                    'message': f"Multiple UID 0 accounts found: {', '.join(uid0_users)}"
                }
            else:
                checks['uid_zero_accounts'] = {
                    'status': 'PASS',
                    'message': "Only root has UID 0"
                }
        
        # Check password aging
        ret_code, output, _ = self.run_command("grep ^PASS_MAX_DAYS /etc/login.defs", shell=True)
        if ret_code == 0:
            max_days = output.split()[-1] if output else "90"
            try:
                if int(max_days) <= 90:
                    checks['password_aging'] = {
                        'status': 'PASS',
                        'message': f"Password max age is {max_days} days (acceptable)"
                    }
                else:
                    checks['password_aging'] = {
                        'status': 'WARN',
                        'message': f"Password max age is {max_days} days (consider reducing)"
                    }
            except ValueError:
                checks['password_aging'] = {
                    'status': 'WARN',
                    'message': "Could not determine password aging policy"
                }
        
        return checks

    def audit_file_permissions(self):
        """Audit critical file permissions"""
        checks = {}
        
        critical_files = {
            '/etc/passwd': ('644', 'World-readable password file'),
            '/etc/shadow': ('640', 'Shadow password file'),
            '/etc/group': ('644', 'Group file'),
            '/etc/gshadow': ('640', 'Shadow group file'),
            '/etc/ssh/sshd_config': ('600', 'SSH daemon configuration'),
        }
        
        for filepath, (perms, desc) in critical_files.items():
            check_name = f"file_perms_{os.path.basename(filepath)}"
            checks[check_name] = self.check_file_permissions(filepath, perms, desc)
        
        # Check for world-writable files in system directories
        ret_code, output, _ = self.run_command("find /etc /bin /sbin /usr/bin /usr/sbin -type f -perm -002 2>/dev/null", shell=True)
        if ret_code == 0:
            writable_files = output.strip().split('\n') if output else []
            if writable_files and writable_files[0]:
                checks['world_writable_system'] = {
                    'status': 'FAIL',
                    'message': f"World-writable system files found: {len(writable_files)} files"
                }
            else:
                checks['world_writable_system'] = {
                    'status': 'PASS',
                    'message': "No world-writable system files found"
                }
        
        return checks

    def audit_network_services(self):
        """Audit network services and open ports"""
        checks = {}
        
        # Check listening ports
        ret_code, output, _ = self.run_command("ss -tuln", shell=True)
        if ret_code == 0:
            listening_ports = []
            for line in output.split('\n')[1:]:  # Skip header
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 5:
                        listening_ports.append(parts[4])
            
            checks['listening_ports'] = {
                'status': 'INFO',
                'message': f"Listening ports: {', '.join(listening_ports[:10])}{'...' if len(listening_ports) > 10 else ''}"
            }
        
        # Check if unnecessary services are running
        dangerous_services = ['telnet', 'ftp', 'rsh', 'rlogin']
        ret_code, output, _ = self.run_command("systemctl list-units --type=service --state=active", shell=True)
        if ret_code == 0:
            active_dangerous = [svc for svc in dangerous_services if svc in output.lower()]
            if active_dangerous:
                checks['dangerous_services'] = {
                    'status': 'FAIL',
                    'message': f"Insecure services running: {', '.join(active_dangerous)}"
                }
            else:
                checks['dangerous_services'] = {
                    'status': 'PASS',
                    'message': "No known insecure services detected"
                }
        
        return checks

    def audit_firewall_status(self):
        """Check firewall configuration"""
        checks = {}
        
        # Check UFW status
        ret_code, output, _ = self.run_command("ufw status")
        if ret_code == 0:
            if "Status: active" in output:
                checks['ufw_status'] = {
                    'status': 'PASS',
                    'message': "UFW firewall is active"
                }
            else:
                checks['ufw_status'] = {
                    'status': 'WARN',
                    'message': "UFW firewall is not active"
                }
        else:
            # Check iptables
            ret_code, output, _ = self.run_command("iptables -L")
            if ret_code == 0:
                if "Chain INPUT (policy ACCEPT)" in output and output.count('\n') > 10:
                    checks['iptables_status'] = {
                        'status': 'PASS',
                        'message': "iptables rules are configured"
                    }
                else:
                    checks['iptables_status'] = {
                        'status': 'WARN',
                        'message': "No firewall rules detected"
                    }
        
        return checks

    def audit_system_updates(self):
        """Check for available system updates"""
        checks = {}
        
        # Check for updates (works on Debian/Ubuntu systems)
        ret_code, output, _ = self.run_command("apt list --upgradable 2>/dev/null | wc -l", shell=True)
        if ret_code == 0:
            try:
                update_count = int(output.strip()) - 1  # Subtract header line
                if update_count > 0:
                    checks['system_updates'] = {
                        'status': 'WARN',
                        'message': f"{update_count} package updates available"
                    }
                else:
                    checks['system_updates'] = {
                        'status': 'PASS',
                        'message': "System is up to date"
                    }
            except ValueError:
                # Try yum for RHEL/CentOS systems
                ret_code, output, _ = self.run_command("yum check-update 2>/dev/null | grep -v '^$' | wc -l", shell=True)
                if ret_code != 0:  # yum check-update returns 100 when updates are available
                    checks['system_updates'] = {
                        'status': 'WARN',
                        'message': "Updates may be available (check with package manager)"
                    }
                else:
                    checks['system_updates'] = {
                        'status': 'PASS',
                        'message': "No updates available"
                    }
        
        return checks

    def audit_ssh_configuration(self):
        """Audit SSH daemon configuration"""
        checks = {}
        sshd_config = '/etc/ssh/sshd_config'
        
        if not os.path.exists(sshd_config):
            checks['ssh_config_exists'] = {
                'status': 'FAIL',
                'message': "SSH configuration file not found"
            }
            return checks
        
        try:
            with open(sshd_config, 'r') as f:
                config_content = f.read()
            
            # Check root login
            if re.search(r'^PermitRootLogin\s+no', config_content, re.MULTILINE | re.IGNORECASE):
                checks['ssh_root_login'] = {'status': 'PASS', 'message': "Root SSH login disabled"}
            elif re.search(r'^PermitRootLogin\s+yes', config_content, re.MULTILINE | re.IGNORECASE):
                checks['ssh_root_login'] = {'status': 'FAIL', 'message': "Root SSH login enabled"}
            else:
                checks['ssh_root_login'] = {'status': 'WARN', 'message': "Root SSH login setting unclear"}
            
            # Check password authentication
            if re.search(r'^PasswordAuthentication\s+no', config_content, re.MULTILINE | re.IGNORECASE):
                checks['ssh_password_auth'] = {'status': 'PASS', 'message': "SSH password authentication disabled"}
            elif re.search(r'^PasswordAuthentication\s+yes', config_content, re.MULTILINE | re.IGNORECASE):
                checks['ssh_password_auth'] = {'status': 'WARN', 'message': "SSH password authentication enabled"}
            else:
                checks['ssh_password_auth'] = {'status': 'WARN', 'message': "SSH password authentication setting unclear"}
            
            # Check protocol version
            if re.search(r'^Protocol\s+2', config_content, re.MULTILINE | re.IGNORECASE):
                checks['ssh_protocol'] = {'status': 'PASS', 'message': "SSH using protocol version 2"}
            elif re.search(r'^Protocol\s+1', config_content, re.MULTILINE | re.IGNORECASE):
                checks['ssh_protocol'] = {'status': 'FAIL', 'message': "SSH using insecure protocol version 1"}
            else:
                checks['ssh_protocol'] = {'status': 'PASS', 'message': "SSH protocol version not explicitly set (defaults to 2)"}
                
        except Exception as e:
            checks['ssh_config_read'] = {
                'status': 'ERROR',
                'message': f"Error reading SSH config: {str(e)}"
            }
        
        return checks

    def audit_kernel_parameters(self):
        """Audit security-related kernel parameters"""
        checks = {}
        
        security_params = {
            'net.ipv4.ip_forward': ('0', 'IP forwarding disabled'),
            'net.ipv4.conf.all.send_redirects': ('0', 'ICMP redirects disabled'),
            'net.ipv4.conf.default.send_redirects': ('0', 'ICMP redirects disabled by default'),
            'net.ipv4.conf.all.accept_source_route': ('0', 'Source routing disabled'),
            'net.ipv4.conf.all.accept_redirects': ('0', 'ICMP redirect acceptance disabled'),
        }
        
        for param, (expected, desc) in security_params.items():
            ret_code, output, _ = self.run_command(f"sysctl -n {param}")
            if ret_code == 0:
                if output.strip() == expected:
                    checks[f'kernel_{param.replace(".", "_")}'] = {
                        'status': 'PASS',
                        'message': f"{desc}: {output.strip()}"
                    }
                else:
                    checks[f'kernel_{param.replace(".", "_")}'] = {
                        'status': 'FAIL',
                        'message': f"{desc}: Expected {expected}, got {output.strip()}"
                    }
        
        return checks

    def run_full_audit(self):
        """Run complete security audit"""
        print("🔐 Linux Security Audit Tool")
        print("=" * 50)
        print(f"Hostname: {self.results['hostname']}")
        print(f"Timestamp: {self.results['timestamp']}")
        print("=" * 50)
        
        audit_functions = [
            ("User Accounts", self.audit_user_accounts),
            ("File Permissions", self.audit_file_permissions),
            ("Network Services", self.audit_network_services),
            ("Firewall Status", self.audit_firewall_status),
            ("System Updates", self.audit_system_updates),
            ("SSH Configuration", self.audit_ssh_configuration),
            ("Kernel Parameters", self.audit_kernel_parameters),
        ]
        
        for section_name, audit_func in audit_functions:
            print(f"\n📋 {section_name}")
            print("-" * 30)
            
            try:
                section_results = audit_func()
                self.results['checks'][section_name.lower().replace(' ', '_')] = section_results
                
                for check_name, result in section_results.items():
                    status = result['status']
                    message = result['message']
                    
                    # Update summary counts
                    if status == 'PASS':
                        self.results['summary']['passed'] += 1
                        icon = "✅"
                    elif status == 'FAIL':
                        self.results['summary']['failed'] += 1
                        icon = "❌"
                    elif status == 'WARN':
                        self.results['summary']['warnings'] += 1
                        icon = "⚠️"
                    else:  # INFO or ERROR
                        icon = "ℹ️"
                    
                    print(f"{icon} {check_name}: {message}")
                    
            except Exception as e:
                error_msg = f"Error running {section_name} audit: {str(e)}"
                print(f"❌ {error_msg}")
                self.results['checks'][section_name.lower().replace(' ', '_')] = {
                    'error': error_msg
                }

    def generate_report(self):
        """Generate summary report"""
        print("\n" + "=" * 50)
        print("📊 SECURITY AUDIT SUMMARY")
        print("=" * 50)
        print(f"✅ Passed: {self.results['summary']['passed']}")
        print(f"❌ Failed: {self.results['summary']['failed']}")
        print(f"⚠️  Warnings: {self.results['summary']['warnings']}")
        
        # Security score calculation
        total_checks = sum(self.results['summary'].values())
        if total_checks > 0:
            score = (self.results['summary']['passed'] / total_checks) * 100
            print(f"\n🎯 Security Score: {score:.1f}%")
            
            if score >= 90:
                print("🟢 Excellent security posture!")
            elif score >= 75:
                print("🟡 Good security, but room for improvement")
            elif score >= 50:
                print("🟠 Moderate security concerns")
            else:
                print("🔴 Significant security issues found")
        
        print("\n💡 RECOMMENDATIONS:")
        if self.results['summary']['failed'] > 0:
            print("- Address all failed security checks immediately")
        if self.results['summary']['warnings'] > 0:
            print("- Review and resolve warning items")
        print("- Run regular security audits")
        print("- Keep system updated with latest security patches")
        print("- Monitor system logs for suspicious activity")

    def save_report(self, filename=None):
        """Save audit results to JSON file"""
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"security_audit_{timestamp}.json"
        
        try:
            with open(filename, 'w') as f:
                json.dump(self.results, f, indent=2)
            print(f"\n💾 Detailed report saved to: {filename}")
        except Exception as e:
            print(f"❌ Error saving report: {str(e)}")


def main():
    """Main function"""
    if os.geteuid() != 0:
        print("⚠️  Warning: Running without root privileges. Some checks may be limited.")
        print("   For complete audit, run with sudo.\n")
    
    auditor = SecurityAuditor()
    
    try:
        auditor.run_full_audit()
        auditor.generate_report()
        auditor.save_report()
    except KeyboardInterrupt:
        print("\n\n⚠️  Audit interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Fatal error during audit: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()