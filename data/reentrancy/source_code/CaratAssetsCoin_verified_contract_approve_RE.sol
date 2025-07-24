/*
 * ===== SmartInject Injection Details =====
 * Function      : approve
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
 * 1. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the spender contract before setting the allowance. This vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added an external call to `tokenRecipient(_spender).receiveApproval()` before setting the allowance
 * 2. The external call happens before the state change (allowance assignment)
 * 3. Uses existing `tokenRecipient` interface already defined in the contract
 * 
 * **Multi-Transaction Exploitation Pattern:**
 * 1. **Transaction 1:** Attacker calls `approve()` with their malicious contract as `_spender`
 * 2. During the external call, the malicious contract re-enters `approve()` with a different value or different spender
 * 3. The nested call sets allowance but then the original call overwrites it
 * 4. **Transaction 2:** Attacker uses `transferFrom()` exploiting the manipulated allowance state from the reentrancy
 * 5. The persistent allowance state enables the exploit across multiple transactions
 * 
 * **Why Multiple Transactions Required:**
 * - The reentrancy manipulates the allowance state during the first transaction
 * - The actual exploitation (token transfer) happens in subsequent `transferFrom()` calls
 * - The vulnerability relies on the persistent allowance mapping state between transactions
 * - Cannot be exploited in a single transaction because the allowance state needs to be consumed via `transferFrom()`
 * 
 * **State Persistence:**
 * - The allowance mapping persists between transactions
 * - Multiple approve calls can create complex allowance states
 * - The vulnerability exploits the timing between state reads and writes across function calls
 */
pragma solidity ^0.4.16;

contract owned {
    address public owner;

    function owned() public {
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

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

contract CaratAssetsCoin {
    string public constant _myTokeName = 'Carat Assets Coin';
    string public constant _mySymbol = 'CTAC';
    uint public constant _myinitialSupply = 21000000;
    uint8 public constant _myDecimal = 0;

    string public name;
    string public symbol;
    uint8 public decimals;
   
    uint256 public totalSupply;

   
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    
    event Transfer(address indexed from, address indexed to, uint256 value);

    function CaratAssetsCoin(
        uint256 initialSupply,
        string TokeName,
        string Symbol
    ) public {
        decimals = _myDecimal;
        totalSupply = _myinitialSupply * (10 ** uint256(_myDecimal)); 
        balanceOf[msg.sender] = initialSupply;               
        name = TokeName;                                   
        symbol = Symbol;                               
    }


    function _transfer(address _from, address _to, uint _value) internal {

        require(_to != 0x0);

        require(balanceOf[_from] >= _value);

        require(balanceOf[_to] + _value > balanceOf[_to]);

        uint previousBalances = balanceOf[_from] + balanceOf[_to];

        balanceOf[_from] -= _value;

        balanceOf[_to] += _value;
        Transfer(_from, _to, _value);

        assert(balanceOf[_from] + balanceOf[_to] == previousBalances);
    }

    function transfer(address _to, uint256 _value) public {
        _transfer(msg.sender, _to, _value);
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);     
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) public
        returns (bool success) {
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Notify spender of approval before setting allowance
        if (_spender != address(0)) { // placeholder to keep vulnerability, code will never run in 0.4.16
            tokenRecipient(_spender).receiveApproval(msg.sender, _value, this, "");
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        allowance[msg.sender][_spender] = _value;
        return true;
    }

    function approveAndCall(address _spender, uint256 _value, bytes _extraData)
        public
        returns (bool success) {
        tokenRecipient spender = tokenRecipient(_spender);
        if (approve(_spender, _value)) {
            spender.receiveApproval(msg.sender, _value, this, _extraData);
            return true;
        }
    }
}
