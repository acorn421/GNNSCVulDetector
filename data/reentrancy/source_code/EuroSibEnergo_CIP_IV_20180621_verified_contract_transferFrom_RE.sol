/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient address after deducting from sender's balance but before crediting the recipient's balance. This creates a vulnerable state window where:
 * 
 * 1. **Multi-Transaction Exploitation**: The vulnerability requires multiple transactions to be exploitable:
 *    - Transaction 1: Attacker sets up allowance and deploys malicious recipient contract
 *    - Transaction 2: Legitimate transferFrom call triggers the vulnerability
 *    - Transaction 3+: Reentrant calls exploit the inconsistent state
 * 
 * 2. **State Accumulation**: The vulnerability depends on accumulated state changes across transactions:
 *    - Initial allowance must be set via approve() in a previous transaction
 *    - Sender must have sufficient balance built up from previous transactions
 *    - The malicious recipient contract must be deployed and prepared in advance
 * 
 * 3. **Vulnerability Mechanism**: During the external call to the recipient, the state is inconsistent:
 *    - allowed[_from][msg.sender] has been decremented
 *    - balances[_from] has been decremented
 *    - balances[_to] has NOT yet been incremented
 *    - This allows the malicious recipient to make additional transferFrom calls with the remaining allowance before the original transfer completes
 * 
 * 4. **Realistic Integration**: The external call appears as a legitimate token notification mechanism, similar to ERC777 or other token standards that notify recipients of transfers.
 * 
 * The vulnerability cannot be exploited in a single transaction because it requires pre-existing allowances and balances that must be established through separate transactions.
 */
pragma solidity ^0.4.8;

contract Ownable {
    address owner;

    function Ownable() public {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }

    function transfertOwnership(address newOwner) public onlyOwner {
        owner = newOwner;
    }
}

contract EuroSibEnergo_CIP_IV_20180621 is Ownable {

    string public constant name = "\tEuroSibEnergo_CIP_IV_20180621\t\t";
    string public constant symbol = "\tESECIPIV\t\t";
    uint32 public constant decimals = 18;
    uint public totalSupply = 0;

    mapping (address => uint) balances;
    mapping (address => mapping(address => uint)) allowed;

    function mint(address _to, uint _value) public onlyOwner {
        assert(totalSupply + _value >= totalSupply && balances[_to] + _value >= balances[_to]);
        balances[_to] += _value;
        totalSupply += _value;
    }

    function balanceOf(address _owner) public constant returns (uint balance) {
        return balances[_owner];
    }

    function transfer(address _to, uint _value) public returns (bool success) {
        if(balances[msg.sender] >= _value && balances[_to] + _value >= balances[_to]) {
            balances[msg.sender] -= _value;
            balances[_to] += _value;
            return true;
        }
        return false;
    }

    function transferFrom(address _from, address _to, uint _value) public returns (bool success) {
        if(allowed[_from][msg.sender] >= _value &&
            balances[_from] >= _value
            && balances[_to] + _value >= balances[_to]) {
            allowed[_from][msg.sender] -= _value;
            balances[_from] -= _value;
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            // INJECTED: External call to recipient before final state update
            // This creates a reentrancy window where state is partially updated
            if (isContract(_to)) {
                _to.call(bytes4(keccak256("onTokenReceived(address,uint256)")), _from, _value);
            }
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            balances[_to] += _value;
            Transfer(_from, _to, _value);
            return true;
        }
        return false;
    }

    function isContract(address _addr) internal view returns (bool) {
        uint256 size;
        assembly {
            size := extcodesize(_addr)
        }
        return size > 0;
    }

    function approve(address _spender, uint _value) public returns (bool success) {
        allowed[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }

    function allowance(address _owner, address _spender) public constant returns (uint remaining) {
        return allowed[_owner][_spender];
    }

    event Transfer(address indexed _from, address indexed _to, uint _value);
    event Approval(address indexed _owner, address indexed _spender, uint _value);
}