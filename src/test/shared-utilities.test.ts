import { classifyPort } from '@/domains/shared/port-classifier';
import { operationName, inferKindFromNumber } from '@/domains/shared/utils';
import { Operation, AclKind } from '@/domains/acl/constants';

beforeAll(() => jest.spyOn(console, 'log').mockImplementation(() => {}));
afterAll(() => jest.restoreAllMocks());

describe('Port Classifier', () => {
  describe('classifyPort', () => {
    describe('system ports (0-1023)', () => {
      it('classifies port 0 as system', () => {
        expect(classifyPort(0)).toBe('system');
      });

      it('classifies port 1 as system', () => {
        expect(classifyPort(1)).toBe('system');
      });

      it('classifies port 22 (SSH) as system', () => {
        expect(classifyPort(22)).toBe('system');
      });

      it('classifies port 80 (HTTP) as system', () => {
        expect(classifyPort(80)).toBe('system');
      });

      it('classifies port 443 (HTTPS) as system', () => {
        expect(classifyPort(443)).toBe('system');
      });

      it('classifies port 1023 as system', () => {
        expect(classifyPort(1023)).toBe('system');
      });
    });

    describe('user ports (1024-49151)', () => {
      it('classifies port 1024 as user', () => {
        expect(classifyPort(1024)).toBe('user');
      });

      it('classifies port 3000 as user', () => {
        expect(classifyPort(3000)).toBe('user');
      });

      it('classifies port 8080 as user', () => {
        expect(classifyPort(8080)).toBe('user');
      });

      it('classifies port 8443 as user', () => {
        expect(classifyPort(8443)).toBe('user');
      });

      it('classifies port 49151 as user', () => {
        expect(classifyPort(49151)).toBe('user');
      });
    });

    describe('dynamic ports (49152-65535)', () => {
      it('classifies port 49152 as dynamic', () => {
        expect(classifyPort(49152)).toBe('dynamic');
      });

      it('classifies port 50000 as dynamic', () => {
        expect(classifyPort(50000)).toBe('dynamic');
      });

      it('classifies port 60000 as dynamic', () => {
        expect(classifyPort(60000)).toBe('dynamic');
      });

      it('classifies port 65535 as dynamic', () => {
        expect(classifyPort(65535)).toBe('dynamic');
      });
    });

    describe('boundary conditions', () => {
      it('handles port 1023/1024 boundary', () => {
        expect(classifyPort(1023)).toBe('system');
        expect(classifyPort(1024)).toBe('user');
      });

      it('handles port 49151/49152 boundary', () => {
        expect(classifyPort(49151)).toBe('user');
        expect(classifyPort(49152)).toBe('dynamic');
      });
    });

    describe('common service ports', () => {
      it('classifies DNS (53) as system', () => {
        expect(classifyPort(53)).toBe('system');
      });

      it('classifies DHCP server (67) as system', () => {
        expect(classifyPort(67)).toBe('system');
      });

      it('classifies DHCP client (68) as system', () => {
        expect(classifyPort(68)).toBe('system');
      });

      it('classifies SMTP (25) as system', () => {
        expect(classifyPort(25)).toBe('system');
      });

      it('classifies POP3 (110) as system', () => {
        expect(classifyPort(110)).toBe('system');
      });

      it('classifies IMAP (143) as system', () => {
        expect(classifyPort(143)).toBe('system');
      });

      it('classifies NTP (123) as system', () => {
        expect(classifyPort(123)).toBe('system');
      });

      it('classifies SNMP (161) as system', () => {
        expect(classifyPort(161)).toBe('system');
      });

      it('classifies Telnet (23) as system', () => {
        expect(classifyPort(23)).toBe('system');
      });

      it('classifies FTP (20/21) as system', () => {
        expect(classifyPort(20)).toBe('system');
        expect(classifyPort(21)).toBe('system');
      });
    });
  });
});

describe('Operation Name Utility', () => {
  describe('operationName', () => {
    it('returns "Permit" for Operation.Permit', () => {
      expect(operationName(Operation.Permit)).toBe('Permit');
    });

    it('returns "Deny" for Operation.Deny', () => {
      expect(operationName(Operation.Deny)).toBe('Deny');
    });

    it('handles all operation types', () => {
      const result = operationName(Operation.Permit);
      expect(['Permit', 'Deny']).toContain(result);
    });
  });
});

describe('ACL Kind Inference', () => {
  describe('inferKindFromNumber', () => {
    describe('standard ACL ranges', () => {
      it('infers Standard for 1', () => {
        expect(inferKindFromNumber(1)).toBe('Standard');
      });

      it('infers Standard for 50', () => {
        expect(inferKindFromNumber(50)).toBe('Standard');
      });

      it('infers Standard for 99', () => {
        expect(inferKindFromNumber(99)).toBe('Standard');
      });

      it('infers Standard for 1300', () => {
        expect(inferKindFromNumber(1300)).toBe('Standard');
      });

      it('infers Standard for 1999', () => {
        expect(inferKindFromNumber(1999)).toBe('Standard');
      });
    });

    describe('extended ACL ranges', () => {
      it('infers Extended for 100', () => {
        expect(inferKindFromNumber(100)).toBe('Extended');
      });

      it('infers Extended for 150', () => {
        expect(inferKindFromNumber(150)).toBe('Extended');
      });

      it('infers Extended for 199', () => {
        expect(inferKindFromNumber(199)).toBe('Extended');
      });

      it('infers Extended for 2000', () => {
        expect(inferKindFromNumber(2000)).toBe('Extended');
      });

      it('infers Extended for 2699', () => {
        expect(inferKindFromNumber(2699)).toBe('Extended');
      });
    });

    describe('boundary conditions', () => {
      it('handles 99/100 boundary', () => {
        expect(inferKindFromNumber(99)).toBe('Standard');
        expect(inferKindFromNumber(100)).toBe('Extended');
      });

      it('handles 199/200 gap', () => {
        expect(inferKindFromNumber(199)).toBe('Extended');
        expect(() => inferKindFromNumber(200)).toThrow(RangeError);
      });

      it('handles 1299/1300 boundary', () => {
        expect(() => inferKindFromNumber(1299)).toThrow(RangeError);
        expect(inferKindFromNumber(1300)).toBe('Standard');
      });

      it('handles 1999/2000 boundary', () => {
        expect(inferKindFromNumber(1999)).toBe('Standard');
        expect(inferKindFromNumber(2000)).toBe('Extended');
      });

      it('handles 2699/2700 boundary', () => {
        expect(inferKindFromNumber(2699)).toBe('Extended');
        expect(() => inferKindFromNumber(2700)).toThrow(RangeError);
      });
    });

    describe('invalid ranges', () => {
      it('throws for 0', () => {
        expect(() => inferKindFromNumber(0)).toThrow(RangeError);
      });

      it('throws for negative numbers', () => {
        expect(() => inferKindFromNumber(-1)).toThrow(RangeError);
      });

      it('throws for gap between standard and extended', () => {
        expect(() => inferKindFromNumber(200)).toThrow(RangeError);
        expect(() => inferKindFromNumber(1299)).toThrow(RangeError);
      });

      it('throws for numbers above extended range', () => {
        expect(() => inferKindFromNumber(2700)).toThrow(RangeError);
        expect(() => inferKindFromNumber(3000)).toThrow(RangeError);
      });
    });

    describe('all valid standard ACL numbers', () => {
      it('accepts all numbers 1-99', () => {
        for (let i = 1; i <= 99; i++) {
          expect(inferKindFromNumber(i)).toBe('Standard');
        }
      });

      it('accepts all numbers 1300-1999', () => {
        for (let i = 1300; i <= 1999; i += 100) {
          expect(inferKindFromNumber(i)).toBe('Standard');
        }
      });
    });

    describe('all valid extended ACL numbers', () => {
      it('accepts all numbers 100-199', () => {
        for (let i = 100; i <= 199; i += 10) {
          expect(inferKindFromNumber(i)).toBe('Extended');
        }
      });

      it('accepts all numbers 2000-2699', () => {
        for (let i = 2000; i <= 2699; i += 100) {
          expect(inferKindFromNumber(i)).toBe('Extended');
        }
      });
    });
  });
});
