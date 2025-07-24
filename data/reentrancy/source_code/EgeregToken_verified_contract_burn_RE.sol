/*
 * ===== SmartInject Injection Details =====
 * Function      : burn
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 3 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to a burn notifier contract between the balance check and state updates. The vulnerability requires:
 * 
 * **Specific Changes Made:**
 * 1. Added an external call to `IBurnNotifier(burnNotifier).onBurn(burner, _value)` after the balance check but before state updates
 * 2. The call is conditional on `burnNotifier != address(0)` to make it realistic (would require adding `address public burnNotifier` state variable and setter function)
 * 3. This violates the Checks-Effects-Interactions pattern by placing the external call (Interactions) before state modifications (Effects)
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker calls `burn(100)` with 100 tokens in their balance
 * 2. **During External Call**: The `onBurn` callback is triggered before state updates
 * 3. **Reentrancy Attack**: From within the callback, attacker calls `burn(50)` again
 * 4. **State Exploitation**: The second call sees the original balance (100) since state hasn't been updated yet
 * 5. **Transaction 2**: Original burn completes, but attacker has now burned 150 tokens while only having 100
 * 6. **State Persistence**: The accumulated state changes persist between transactions, allowing the attacker to exploit the time window
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability relies on the external call creating a window where state is inconsistent
 * - Each reentrancy call operates on stale state from previous transactions
 * - The attacker needs to accumulate multiple burn operations before the state is finally updated
 * - Single-transaction atomic operations would prevent this type of state manipulation
 * - The exploit requires the external contract to maintain state between calls to orchestrate the attack
 * 
 * **Realistic Integration:**
 * - Burn notifications are common in DeFi protocols for oracle updates, registry maintenance, or cross-chain synchronization
 * - The conditional check makes the code appear production-ready
 * - The vulnerability is subtle and could easily be missed in code reviews
 */
pragma solidity ^0.4.23;

contract TokenReceiver {
    function tokenFallback(address _from, uint _value, bytes _data) public;
}

// Interface for burn notifier
interface IBurnNotifier {
    function onBurn(address burner, uint256 value) external;
}

contract EgeregToken {
    address public owner;
    string public name = "EgeregToken";
    string public symbol = "MNG";
    uint8 public decimals = 2;
    uint public totalSupply = 0;
    mapping(address => uint) balances;
    mapping (address => mapping (address => uint)) internal allowed;
    
    // Declare burnNotifier variable
    address public burnNotifier;

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
        totalSupply = addit(totalSupply, _amount);
        balances[_to] = addit(balances[_to], _amount);
        emit Mint(_to, _amount);
        emit Transfer(address(0), _to, _amount);
        return true;
    }

    function burn(uint _value) external {
        require(_value <= balances[msg.sender]);
        address burner = msg.sender;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Notify external burn handler before state updates (VULNERABILITY INJECTION)
        if (burnNotifier != address(0)) {
            IBurnNotifier(burnNotifier).onBurn(burner, _value);
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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