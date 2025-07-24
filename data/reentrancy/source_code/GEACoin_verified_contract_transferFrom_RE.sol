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
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful multi-transaction reentrancy vulnerability by adding an external call to the recipient address after balance updates but before allowance updates. This creates a critical window where balances are updated but allowances haven't been decremented yet.
 * 
 * **Specific Changes Made:**
 * 1. Added external call `_to.call(abi.encodeWithSignature("onTokenReceived(address,address,uint256)", _from, _to, _value))` after balance updates
 * 2. Moved the allowance update `allowed[_from][msg.sender] = allowed[_from][msg.sender].sub(_value)` to occur AFTER the external call
 * 3. Added a contract existence check `_to.code.length > 0` to make the vulnerability more realistic
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * Transaction 1: Attacker sets up initial state by getting approval from victim and deploying malicious contract
 * Transaction 2: Attacker calls transferFrom, which triggers the external call to their malicious contract
 * Transaction 3: During the callback, the malicious contract calls transferFrom again while the allowance hasn't been updated yet
 * Transaction 4: The second transferFrom call succeeds because the allowance check passes (allowance not yet decremented)
 * 
 * **Why Multiple Transactions Are Required:**
 * - The vulnerability requires pre-existing approval state from a previous transaction
 * - The reentrancy exploit depends on the specific timing of state updates across multiple calls
 * - The allowance state must be established before the attack can be executed
 * - The attack relies on the persistent state inconsistency that exists between balance updates and allowance updates across multiple function calls
 * 
 * This creates a realistic stateful reentrancy where an attacker can drain more tokens than they should be allowed to transfer by exploiting the window between balance and allowance updates.
 */
pragma solidity ^0.4.25;

library SafeMath {
  function mul(uint256 a, uint256 b) internal pure returns (uint256) {
    uint256 c = a * b;
    assert(a == 0 || c / a == b);
    return c;
  }

  function div(uint256 a, uint256 b) internal pure returns (uint256) {
    assert(b > 0); // Solidity automatically throws when dividing by 0
    uint256 c = a / b;
    assert(a == b * c + a % b); // There is no case in which this doesn't hold
    return c;
  }

  function sub(uint256 a, uint256 b) internal pure returns (uint256) {
    assert(b <= a);
    return a - b;
  }

  function add(uint256 a, uint256 b) internal pure returns (uint256) {
    uint256 c = a + b;
    assert(c >= a);
    return c;
  }
}

// ERC20 Token Smart Contract
contract GEACoin {
    
    string public constant name = "GEACoin";
    string public constant symbol = "GEAC";
    uint8 public constant decimals = 8;
    uint public _totalSupply = 5000000000000000;
    uint256 public RATE = 1;
    bool public isMinting = false;
    string public constant generatedBy  = "Togen.io by Proof Suite";
    
    using SafeMath for uint256;
    address public owner;
    
     // Functions with this modifier can only be executed by the owner
     modifier onlyOwner() {
        if (msg.sender != owner) {
            revert();
        }
         _;
     }
 
    // Balances for each account
    mapping(address => uint256) balances;
    // Owner of account approves the transfer of an amount to another account
    mapping(address => mapping(address=>uint256)) allowed;

    // Its a payable function works as a token factory.
    function () public payable {
        createTokens();
    }

    // Constructor
    constructor() public {
        owner = 0xF525F66D9207C273748be7dDA455d185B950ee12; 
        balances[owner] = _totalSupply;
    }

    //allows owner to burn tokens that are not sold in a crowdsale
    function burnTokens(uint256 _value) public onlyOwner {

         require(balances[msg.sender] >= _value && _value > 0 );
         _totalSupply = _totalSupply.sub(_value);
         balances[msg.sender] = balances[msg.sender].sub(_value);
         
    }


    // This function creates Tokens  
     function createTokens() public payable {
        if(isMinting == true){
            require(msg.value > 0);
            uint256  tokens = msg.value.div(100000000000000).mul(RATE);
            balances[msg.sender] = balances[msg.sender].add(tokens);
            _totalSupply = _totalSupply.add(tokens);
            owner.transfer(msg.value);
        }
        else{
            revert();
        }
    }


    function endCrowdsale() public onlyOwner {
        isMinting = false;
    }

    function changeCrowdsaleRate(uint256 _value) public onlyOwner {
        RATE = _value;
    }


    
    function totalSupply() public view returns(uint256){
        return _totalSupply;
    }
    // What is the balance of a particular account?
    function balanceOf(address _owner) public view returns(uint256){
        return balances[_owner];
    }

     // Transfer the balance from owner's account to another account   
    function transfer(address _to, uint256 _value) public returns(bool) {
        require(balances[msg.sender] >= _value && _value > 0 );
        balances[msg.sender] = balances[msg.sender].sub(_value);
        balances[_to] = balances[_to].add(_value);
        emit Transfer(msg.sender, _to, _value);
        return true;
    }
    
    // Send _value amount of tokens from address _from to address _to
    // The transferFrom method is used for a withdraw workflow, allowing contracts to send
    // tokens on your behalf, for example to "deposit" to a contract address and/or to charge
    // fees in sub-currencies; the command should fail unless the _from account has
    // deliberately authorized the sender of the message via some mechanism; we propose
    // these standardized APIs for approval:
    function transferFrom(address _from, address _to, uint256 _value) public returns(bool) {
        require(allowed[_from][msg.sender] >= _value && balances[_from] >= _value && _value > 0);
        balances[_from] = balances[_from].sub(_value);
        balances[_to] = balances[_to].add(_value);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify recipient contract of token receipt - introduces reentrancy vulnerability
        if (isContract(_to)) {
            // This will call the onTokenReceived function on the recipient contract
            require(_to.call(abi.encodeWithSignature("onTokenReceived(address,address,uint256)", _from, _to, _value)));
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        allowed[_from][msg.sender] = allowed[_from][msg.sender].sub(_value);
        emit Transfer(_from, _to, _value);
        return true;
    }

    // Helper to check if address is a contract
    function isContract(address _addr) internal view returns (bool) {
        uint size;
        assembly { size := extcodesize(_addr) }
        return size > 0;
    }

    // Allow _spender to withdraw from your account, multiple times, up to the _value amount.
    // If this function is called again it overwrites the current allowance with _value.
    function approve(address _spender, uint256 _value) public returns(bool){
        allowed[msg.sender][_spender] = _value; 
        emit Approval(msg.sender, _spender, _value);
        return true;
    }

    // Returns the amount which _spender is still allowed to withdraw from _owner
    function allowance(address _owner, address _spender) public view returns(uint256){
        return allowed[_owner][_spender];
    }

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}
