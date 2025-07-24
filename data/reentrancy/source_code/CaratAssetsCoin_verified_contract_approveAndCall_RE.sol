/*
 * ===== SmartInject Injection Details =====
 * Function      : approveAndCall
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
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * Introduced stateful, multi-transaction reentrancy vulnerability by adding persistent state variables (pendingApprovals, hasActiveApproval) that track approval states across transactions. The vulnerability requires multiple transactions to exploit:
 * 
 * 1. **First Transaction**: Attacker calls approveAndCall, which increments pendingApprovals and sets hasActiveApproval=true after the external call
 * 2. **Reentrant Call**: During receiveApproval callback, attacker can call approveAndCall again, further incrementing pendingApprovals while hasActiveApproval is still false
 * 3. **State Manipulation**: The pending approval counter accumulates across calls, and the hasActiveApproval flag creates inconsistent state
 * 4. **Exploitation**: Attacker can exploit the accumulated pendingApprovals value in subsequent transactions or through complex callback sequences
 * 
 * The vulnerability is multi-transaction because:
 * - State persists between calls via mapping variables
 * - The approval tracking logic depends on accumulated state from previous transactions
 * - Full exploitation requires building up pendingApprovals across multiple calls
 * - The hasActiveApproval flag creates time-dependent state windows that can be exploited across transaction boundaries
 * 
 * This creates a realistic vulnerability where an attacker must perform multiple transactions to build up the exploitable state, making it impossible to exploit in a single atomic transaction.
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

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; }

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
        allowance[msg.sender][_spender] = _value;
        return true;
    }

    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
mapping (address => uint256) public pendingApprovals;
    mapping (address => bool) public hasActiveApproval;

    function approveAndCall(address _spender, uint256 _value, bytes _extraData)
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        public
        returns (bool success) {
        tokenRecipient spender = tokenRecipient(_spender);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Track pending approvals across transactions
        pendingApprovals[msg.sender] += _value;
        
        if (approve(_spender, _value)) {
            // External call before clearing pending state - reentrancy window
            spender.receiveApproval(msg.sender, _value, this, _extraData);
            
            // State update after external call - vulnerable to reentrancy
            hasActiveApproval[msg.sender] = true;
            
            // Only clear pending if no active approval exists
            if (!hasActiveApproval[msg.sender]) {
                pendingApprovals[msg.sender] = 0;
            }
            
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            return true;
        }
    }
}