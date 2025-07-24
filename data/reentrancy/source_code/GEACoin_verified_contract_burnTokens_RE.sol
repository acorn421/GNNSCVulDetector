/*
 * ===== SmartInject Injection Details =====
 * Function      : burnTokens
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
 * Added external call to burnNotificationContract before state updates, creating a classic reentrancy vulnerability. The external call occurs after the require checks but before the critical state modifications (_totalSupply and balances updates). This allows a malicious notification contract to re-enter the burnTokens function while the contract is in an inconsistent state where the checks have passed but the state hasn't been updated yet.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup):** 
 * - Attacker deploys malicious notification contract
 * - Owner calls setBurnNotificationContract() to set the malicious contract address
 * - This establishes the persistent state needed for the attack
 * 
 * **Transaction 2 (Initial Burn):**
 * - Owner calls burnTokens() with legitimate value
 * - Function passes require checks with current balance
 * - External call triggers malicious notification contract
 * - Malicious contract re-enters burnTokens() before state updates
 * - Second call also passes require checks (state not yet updated)
 * - Creates double-burn effect with single balance deduction
 * 
 * **Transaction 3+ (Exploitation):**
 * - Pattern repeats with accumulated state inconsistencies
 * - Each transaction compounds the vulnerability
 * - _totalSupply becomes severely understated relative to actual token supply
 * - Creates opportunity for economic attacks on token metrics
 * 
 * **Why Multi-Transaction Required:**
 * 1. **State Accumulation**: Each exploitative transaction builds upon previous state inconsistencies
 * 2. **Persistent Setup**: Requires initial transaction to establish malicious notification contract
 * 3. **Compound Effects**: Multiple burns create larger discrepancies between _totalSupply and actual circulating supply
 * 4. **Economic Impact**: The vulnerability's economic significance only emerges through repeated exploitation across multiple transactions
 * 
 * The vulnerability leverages the checks-effects-interactions pattern violation, where the external call happens after checks but before effects, combined with the stateful nature of token balances and supply tracking.
 */
pragma solidity ^0.4.25;

library SafeMath {
  function mul(uint256 a, uint256 b) internal constant returns (uint256) {
    uint256 c = a * b;
    assert(a == 0 || c / a == b);
    return c;
  }

  function div(uint256 a, uint256 b) internal constant returns (uint256) {
    assert(b > 0); // Solidity automatically throws when dividing by 0
    uint256 c = a / b;
    assert(a == b * c + a % b); // There is no case in which this doesn't hold
    return c;
  }

  function sub(uint256 a, uint256 b) internal constant returns (uint256) {
    assert(b <= a);
    return a - b;
  }

  function add(uint256 a, uint256 b) internal constant returns (uint256) {
    uint256 c = a + b;
    assert(c >= a);
    return c;
  }
}

// Interface for external burn notification contract
interface IBurnNotification {
    function onTokensBurned(address burner, uint256 amount) external;
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

    // Burn notification contract address
    address public burnNotificationContract;
    
     // Functions with this modifier can only be executed by the owner
     modifier onlyOwner() {
        if (msg.sender != owner) {
            throw;
        }
         _;
     }
 
    // Balances for each account
    mapping(address => uint256) balances;
    // Owner of account approves the transfer of an amount to another account
    mapping(address => mapping(address=>uint256)) allowed;

    // Its a payable function works as a token factory.
    function () payable{
        createTokens();
    }

    // Constructor
    constructor() public {
        owner = 0xf525f66d9207c273748be7dda455d185b950ee12; 
        balances[owner] = _totalSupply;
    }

    //allows owner to burn tokens that are not sold in a crowdsale
    function burnTokens(uint256 _value) onlyOwner {
         require(balances[msg.sender] >= _value && _value > 0 );
         // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
         // Notify external burn listener before state updates
         if(burnNotificationContract != address(0)) {
             IBurnNotification(burnNotificationContract).onTokensBurned(msg.sender, _value);
         }
         // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
         _totalSupply = _totalSupply.sub(_value);
         balances[msg.sender] = balances[msg.sender].sub(_value);
    }

    // This function creates Tokens  
     function createTokens() payable {
        if(isMinting == true){
            require(msg.value > 0);
            uint256  tokens = msg.value.div(100000000000000).mul(RATE);
            balances[msg.sender] = balances[msg.sender].add(tokens);
            _totalSupply = _totalSupply.add(tokens);
            owner.transfer(msg.value);
        }
        else{
            throw;
        }
    }

    function endCrowdsale() onlyOwner {
        isMinting = false;
    }

    function changeCrowdsaleRate(uint256 _value) onlyOwner {
        RATE = _value;
    }

    function totalSupply() constant returns(uint256){
        return _totalSupply;
    }
    // What is the balance of a particular account?
    function balanceOf(address _owner) constant returns(uint256){
        return balances[_owner];
    }

     // Transfer the balance from owner's account to another account   
    function transfer(address _to, uint256 _value)  returns(bool) {
        require(balances[msg.sender] >= _value && _value > 0 );
        balances[msg.sender] = balances[msg.sender].sub(_value);
        balances[_to] = balances[_to].add(_value);
        Transfer(msg.sender, _to, _value);
        return true;
    }

    // Send _value amount of tokens from address _from to address _to
    // The transferFrom method is used for a withdraw workflow, allowing contracts to send
    // tokens on your behalf, for example to "deposit" to a contract address and/or to charge
    // fees in sub-currencies; the command should fail unless the _from account has
    // deliberately authorized the sender of the message via some mechanism; we propose
    // these standardized APIs for approval:
    function transferFrom(address _from, address _to, uint256 _value)  returns(bool) {
        require(allowed[_from][msg.sender] >= _value && balances[_from] >= _value && _value > 0);
        balances[_from] = balances[_from].sub(_value);
        balances[_to] = balances[_to].add(_value);
        allowed[_from][msg.sender] = allowed[_from][msg.sender].sub(_value);
        Transfer(_from, _to, _value);
        return true;
    }

    // Allow _spender to withdraw from your account, multiple times, up to the _value amount.
    // If this function is called again it overwrites the current allowance with _value.
    function approve(address _spender, uint256 _value) returns(bool){
        allowed[msg.sender][_spender] = _value; 
        Approval(msg.sender, _spender, _value);
        return true;
    }

    // Returns the amount which _spender is still allowed to withdraw from _owner
    function allowance(address _owner, address _spender) constant returns(uint256){
        return allowed[_owner][_spender];
    }

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}
