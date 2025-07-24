/*
 * ===== SmartInject Injection Details =====
 * Function      : mint
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-benign (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * This injection creates a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Specific Changes Made:**
 *    - Added external call to `TokenReceiver.tokenFallback()` BEFORE updating the recipient's balance
 *    - Moved the balance update (`balances[_to] = addit(balances[_to], _amount)`) to occur AFTER the external call
 *    - Maintained the totalSupply update before the external call to create an inconsistent state window
 * 
 * 2. **Multi-Transaction Exploitation Pattern:**
 *    - **Transaction 1**: Owner calls `mint(maliciousContract, 1000)` → totalSupply increases by 1000 → external call to maliciousContract.tokenFallback() → maliciousContract reenters and calls mint() again while balances[maliciousContract] is still 0 → second mint() sees totalSupply already increased but balances still old → creates state inconsistency
 *    - **Transaction 2**: Attacker exploits the inconsistent state where totalSupply reflects multiple mints but balances may not be properly updated, allowing double-spending or balance manipulation
 *    - **Transaction 3**: Attacker can transfer tokens that were improperly accounted for due to the reentrancy-induced state inconsistency
 * 
 * 3. **Why Multiple Transactions Are Required:**
 *    - The vulnerability creates a persistent state inconsistency between `totalSupply` and `balances` that must be exploited across multiple transactions
 *    - Single transaction exploitation is prevented because the reentrancy guard would need to be bypassed, but the real exploitation occurs when the attacker uses the inconsistent state in subsequent transactions
 *    - The attack requires: (1) Initial mint call with reentrancy, (2) Exploitation of inconsistent state, (3) Potential cleanup or further exploitation
 *    - State changes persist between transactions, enabling the attacker to leverage the inconsistent accounting system created by the reentrancy
 * 
 * The vulnerability is realistic because it uses the existing TokenReceiver interface from the contract and creates a logical callback mechanism that would appear as a legitimate feature enhancement.
 */
pragma solidity ^0.4.23;

contract TokenReceiver {
    function tokenFallback(address _from, uint _value, bytes _data) public;
}

contract EgeregToken {
    address public owner;
    string public name = "EgeregToken";
    string public symbol = "MNG";
    uint8 public decimals = 2;
    uint public totalSupply = 0;
    mapping(address => uint) balances;
    mapping (address => mapping (address => uint)) internal allowed;

    constructor() public {
        owner = msg.sender;
    }

    function subtr(uint a, uint b) internal pure returns (uint) {
        assert(b <= a);
        return a - b;
    }

    function addit(uint a, uint b) internal pure returns (uint) {
        uint c = a + b;
        assert(c >= a);
        return c;
    }

    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }

    function balanceOf(address _owner) external view returns (uint) {
        return balances[_owner];
    }

    function transfer(address _to, uint _value) external returns (bool) {
        bytes memory empty;
        transfer(_to, _value, empty);
        return true;
    }

    function transfer(address _to, uint _value, bytes _data) public returns (bool) {
        require(_value <= balances[msg.sender]);
        balances[msg.sender] = subtr(balances[msg.sender], _value);
        balances[_to] = addit(balances[_to], _value);
        emit Transfer(msg.sender, _to, _value);
        if (isContract(_to)) {
            TokenReceiver receiver = TokenReceiver(_to);
            receiver.tokenFallback(msg.sender, _value, _data);
        }
        return true;
    }

    function transferFrom(address _from, address _to, uint _value) external returns (bool) {
        require(_to != address(0));
        require(_value <= balances[_from]);
        require(_value <= allowed[_from][msg.sender]);
        balances[_from] = subtr(balances[_from], _value);
        balances[_to] = addit(balances[_to], _value);
        allowed[_from][msg.sender] = subtr(allowed[_from][msg.sender], _value);
        emit Transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint _value) public returns (bool) {
        allowed[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }

    function approve(address _spender, uint _value, bytes _data) external returns (bool) {
        approve(_spender, _value);
        require(_spender.call(_data));
        return true;
    }

    function allowance(address _owner, address _spender) external view returns (uint) {
        return allowed[_owner][_spender];
    }

    function increaseApproval(address _spender, uint _addedValue) public returns (bool) {
        allowed[msg.sender][_spender] = addit(allowed[msg.sender][_spender], _addedValue);
        emit Approval(msg.sender, _spender, allowed[msg.sender][_spender]);
        return true;
    }

    function increaseApproval(address _spender, uint _addedValue, bytes _data) external returns (bool) {
        increaseApproval(_spender, _addedValue);
        require(_spender.call(_data));
        return true;
    }

    function decreaseApproval(address _spender, uint _subtractedValue) external returns (bool) {
        uint oldValue = allowed[msg.sender][_spender];
        if (_subtractedValue > oldValue) {
            allowed[msg.sender][_spender] = 0;
        } else {
            allowed[msg.sender][_spender] = subtr(oldValue, _subtractedValue);
        }
        emit Approval(msg.sender, _spender, allowed[msg.sender][_spender]);
        return true;
    }

    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0));
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }

    function mint(address _to, uint _amount) onlyOwner external returns (bool) {
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // First update totalSupply to indicate mint is in progress
        totalSupply = addit(totalSupply, _amount);
        
        // Notify recipient contract about minting - EXTERNAL CALL BEFORE BALANCE UPDATE
        if (isContract(_to)) {
            TokenReceiver receiver = TokenReceiver(_to);
            receiver.tokenFallback(msg.sender, _amount, "");
        }
        
        // Update recipient balance AFTER external call - VULNERABLE TO REENTRANCY
        balances[_to] = addit(balances[_to], _amount);
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        emit Mint(_to, _amount);
        emit Transfer(address(0), _to, _amount);
        return true;
    }

    function burn(uint _value) external {
        require(_value <= balances[msg.sender]);
        address burner = msg.sender;
        balances[burner] = subtr(balances[burner], _value);
        totalSupply = subtr(totalSupply, _value);
        emit Burn(burner, _value);
        emit Transfer(burner, address(0), _value);
    }

    function isContract(address _addr) private view returns (bool) {
        uint length;
        assembly {
            length := extcodesize(_addr)
        }
        return (length>0);
    }

    event Transfer(address indexed from, address indexed to, uint value);
    event Approval(address indexed owner, address indexed spender, uint value);
    event Mint(address indexed to, uint amount);
    event Burn(address indexed burner, uint value);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
}