/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 0 issues
 * Retry Count   : 0
 *
 * === Description ===
 * **Specific Changes Made:**
 * 1. **Added External Call Before State Update**: Introduced a low-level call to `_to.call()` that invokes `onTokenTransfer` on the recipient contract if it has code, positioned strategically before the allowance state update.
 * 2. **State Update Vulnerability Window**: The allowance decrease now happens after the external call, creating a reentrancy window where the original allowance value is still available.
 * 3. **Preserved Function Logic**: Maintained all original functionality including the require check, _transfer call, and return value.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup Phase):**
 * - Attacker approves themselves (or accomplice) a significant allowance amount via `approve()`
 * - This sets up the persistent state: `allowance[victim][attacker] = largeAmount`
 * 
 * **Transaction 2 (Exploit Phase):**
 * - Attacker calls `transferFrom(victim, maliciousContract, amount)` 
 * - The malicious contract implements `onTokenTransfer()` to reenter `transferFrom()`
 * - During reentrancy, the allowance hasn't been decreased yet, so the require check passes
 * - This allows multiple transfers using the same allowance amount
 * 
 * **Why Multi-Transaction is Required:**
 * 1. **State Accumulation**: The allowance must be established in prior transactions through `approve()` calls
 * 2. **Persistent State Dependency**: The vulnerability exploits the fact that allowance state persists between transactions and multiple users can interact with the same allowance values
 * 3. **Complex Setup**: The malicious recipient contract needs to be deployed and the allowance established before exploitation can occur
 * 4. **Stateful Exploitation**: Each reentrancy call depends on the allowance state that was set up in previous transactions, making it impossible to exploit atomically
 * 
 * **Vulnerability Mechanism:**
 * - The external call creates a reentrancy opportunity before allowance state is updated
 * - Multiple `transferFrom` calls can be made using the same allowance amount
 * - The vulnerability requires the allowance to be pre-established across multiple transactions
 * - State changes persist between calls, enabling accumulated exploitation over time
 */
pragma solidity >=0.4.21 <0.6.0;

contract Owner {
    address public owner;

    constructor() public {
        owner = msg.sender;
    }

    modifier onlyOwner {
        require(msg.sender == owner);
        _;
    }

    function transferOwnership(address newOwner) onlyOwner public {
        owner = newOwner;
    }
}

interface tokenRecipient {
    function receiveApproval(
        address _from,
        uint256 _value,
        address _token,
        bytes _extraData)
    external;
}

contract ERC20Token {
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);

    event Burn(address indexed from, uint256 value);

    constructor(
        string memory _tokenName,
        string memory _tokenSymbol,
        uint8 _decimals,
        uint256 _totalSupply) public {
        name = _tokenName;
        symbol = _tokenSymbol;
        decimals = _decimals;
        totalSupply = _totalSupply * 10 ** uint256(decimals);
        balanceOf[msg.sender] = totalSupply;
    }

    function _transfer(
        address _from,
        address _to,
        uint256 _value) internal {
        require(_to != address(0));
        require(_from != address(0));
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value > balanceOf[_to]);

        uint256 previousBalances = balanceOf[_from] + balanceOf[_to];

        balanceOf[_from] -= _value;
        balanceOf[_to] += _value;

        emit Transfer(_from, _to, _value);

        assert(balanceOf[_from] + balanceOf[_to] == previousBalances);
    }

    function transfer(
        address _to,
        uint256 _value) public {
        _transfer(msg.sender, _to, _value);
    }

    function transferFrom(
        address _from,
        address _to,
        uint256 _value) public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Call external contract for transfer notification before state update
        // This allows reentrancy with stale allowance state
        uint256 size;
        assembly { size := extcodesize(_to) }
        if (size > 0) {
            (bool callSuccess,) = _to.call(abi.encodeWithSignature("onTokenTransfer(address,address,uint256)", _from, _to, _value));
            // Continue regardless of call success to maintain functionality
        }
        
        // State update occurs after external call - vulnerable to reentrancy
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        allowance[_from][msg.sender] -= _value;
        
        _transfer(_from, _to, _value);
        
        return true;
    }

    function approve(
        address _spender,
        uint256 _value) public returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        
        return true;
    }

    function approveAndCall(
        address _spender,
        uint256 _value,
        bytes memory _extraData) public returns (bool success) {
        tokenRecipient spender = tokenRecipient(_spender);

        if (approve(_spender, _value)) {
            spender.receiveApproval(msg.sender, _value, address(this), _extraData);
            
            return true;
        }
    }

    function burn(
        uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);

        balanceOf[msg.sender] -= _value;
        totalSupply -= _value;

        emit Burn(msg.sender, _value);

        return true;
    }

    function burnFrom(
        address _from,
        uint256 _value) public returns (bool success) {
        require(balanceOf[_from] >= _value);
        require(_value <= allowance[_from][msg.sender]);

        balanceOf[_from] -= _value;
        allowance[_from][msg.sender] -= _value;
        totalSupply -= _value;

        emit Burn(_from, _value);

        return true;
    }
}

contract Stmp is Owner, ERC20Token {
    constructor(
        string memory _tokenName,
        string memory _tokenSymbol,
        uint8 _decimals,
        uint256 _totalSupply)
        ERC20Token(_tokenName, _tokenSymbol, _decimals, _totalSupply) public {
    }

    function transferStmpsToOwnerAccount(
        address _from,
        uint256 _value) onlyOwner public {
        _transfer(_from, owner, _value);
    }
}