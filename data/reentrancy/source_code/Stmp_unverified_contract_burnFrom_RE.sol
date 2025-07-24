/*
 * ===== SmartInject Injection Details =====
 * Function      : burnFrom
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to notify the token holder about burns BEFORE updating the allowance mapping. This creates a classic reentrancy pattern where:
 * 
 * 1. **External Call Before State Update**: Added a call to `_from` address using `onTokenBurn(address,uint256)` signature before the allowance is decremented
 * 2. **State Update After External Call**: Moved the allowance update to occur AFTER the external call, violating the Checks-Effects-Interactions pattern
 * 3. **Stateful Nature**: The vulnerability relies on the persistent allowance mapping state across transactions
 * 
 * **Multi-Transaction Exploitation Scenario**:
 * - **Setup**: Attacker creates a malicious contract and gets approval for burning tokens
 * - **Transaction 1**: Attacker calls `burnFrom()`, which triggers the callback to attacker's contract
 * - **During Callback**: Attacker's contract calls `burnFrom()` again with the same allowance (not yet decremented)
 * - **Transaction 2+**: Process repeats, allowing attacker to burn more tokens than initially approved
 * - **State Persistence**: The allowance mapping retains its value between transactions, enabling repeated exploitation
 * 
 * **Why Multi-Transaction Required**: 
 * - The attacker needs separate transactions to set up the initial allowance and then exploit it
 * - Each exploitation cycle requires the allowance to be checked but not yet decremented
 * - The vulnerability accumulates damage across multiple calls rather than being exploitable in a single atomic transaction
 * - The persistent state (allowance mapping) enables the vulnerability to be effective across transaction boundaries
 * 
 * This creates a realistic vulnerability where an attacker can burn significantly more tokens than approved by exploiting the timing window between the external call and allowance update.
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        totalSupply -= _value;

        // Notify the token holder about the burn - VULNERABILITY: External call before allowance update
        if (_from != address(0) && isContract(_from)) {
            (bool callSuccess,) = _from.call(abi.encodeWithSignature("onTokenBurn(address,uint256)", msg.sender, _value));
            // Continue execution regardless of call result
        }

        // VULNERABILITY: Allowance update happens AFTER external call
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        allowance[_from][msg.sender] -= _value;

        emit Burn(_from, _value);

        return true;
    }
    
    function isContract(address _addr) internal view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(_addr) }
        return size > 0;
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
