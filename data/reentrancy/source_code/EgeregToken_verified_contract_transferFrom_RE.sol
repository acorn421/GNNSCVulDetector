/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract (tokenFallback) BEFORE the allowance is decreased. This creates a classic Checks-Effects-Interactions pattern violation where the external call happens before all state changes are complete. The vulnerability requires multiple transactions to exploit:
 * 
 * 1. **Transaction 1**: Attacker gets approval from token holder for a specific amount
 * 2. **Transaction 2**: Attacker calls transferFrom, which triggers the vulnerable callback
 * 3. **Reentrant calls**: During the callback, the attacker can recursively call transferFrom again since the allowance hasn't been decreased yet
 * 
 * The attack exploits the persistent state of the allowance mapping across multiple transactions. The allowance remains unchanged during the external call, allowing the attacker to drain more tokens than originally approved. This is a realistic vulnerability pattern seen in production token contracts where callbacks are added for compatibility with other contracts but create reentrancy opportunities.
 * 
 * The vulnerability is stateful because it depends on the pre-existing allowance set in a previous transaction, and multi-transaction because the exploit requires the initial approval transaction followed by the transferFrom call that enables the reentrancy attack.
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        emit Transfer(_from, _to, _value);
        
        // External call to recipient before allowance is decreased
        if (isContract(_to)) {
            TokenReceiver receiver = TokenReceiver(_to);
            receiver.tokenFallback(_from, _value, "");
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        allowed[_from][msg.sender] = subtr(allowed[_from][msg.sender], _value);
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
        totalSupply = addit(totalSupply, _amount);
        balances[_to] = addit(balances[_to], _amount);
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