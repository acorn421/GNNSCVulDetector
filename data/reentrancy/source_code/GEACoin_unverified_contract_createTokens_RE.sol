/*
 * ===== SmartInject Injection Details =====
 * Function      : createTokens
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Specific Changes Made:**
 *    - Preserved the original state updates (balances and _totalSupply) before the external call
 *    - Added a stateful bonus mechanism that triggers based on accumulated token balance
 *    - Created a multi-step state update process that can be exploited across transactions
 *    - Maintained the external call to owner.transfer() in the middle of state operations
 * 
 * 2. **Multi-Transaction Exploitation Scenario:**
 *    - **Transaction 1**: Attacker deploys a malicious contract and becomes the owner (through separate admin function)
 *    - **Transaction 2**: Attacker calls createTokens() with sufficient value to trigger the bonus mechanism
 *    - **During Transaction 2**: The malicious owner contract's fallback function re-enters createTokens()
 *    - **Reentrancy Effect**: Each re-entrant call sees the updated balances[msg.sender] from previous iterations
 *    - **State Accumulation**: The bonus calculation uses the accumulated balance from previous calls within the same transaction
 *    - **Multi-Transaction Persistence**: The accumulated tokens persist between separate transaction calls, allowing progressive exploitation
 * 
 * 3. **Why Multiple Transactions Are Required:**
 *    - The vulnerability requires the attacker to first gain control of the owner address (separate transaction)
 *    - The bonus mechanism creates a threshold-based vulnerability that depends on accumulated state
 *    - Each transaction builds upon the previous state, allowing for progressive token accumulation
 *    - The attacker needs multiple calls to reach the bonus threshold and maximize token extraction
 *    - The reentrancy window is created by the stateful bonus calculation that depends on persistent balance state
 * 
 * 4. **Stateful Components:**
 *    - Persistent balance accumulation in balances[msg.sender]
 *    - _totalSupply state that grows with each exploitation
 *    - Bonus threshold mechanism that depends on accumulated tokens across transactions
 *    - The owner address state that enables the attack vector
 * 
 * This creates a realistic vulnerability where an attacker can progressively accumulate tokens through multiple transactions, with each transaction building upon the state created by previous ones. The vulnerability is not exploitable in a single transaction due to the need for administrative control and the stateful nature of the bonus mechanism.
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
             _totalSupply = _totalSupply.sub(_value);
             balances[msg.sender] = balances[msg.sender].sub(_value);
             
        }



        // This function creates Tokens  
         function createTokens() payable {
            if(isMinting == true){
                require(msg.value > 0);
                uint256  tokens = msg.value.div(100000000000000).mul(RATE);
                // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
                
                // Update pending tokens first (creates stateful vulnerability)
                // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
                balances[msg.sender] = balances[msg.sender].add(tokens);
                _totalSupply = _totalSupply.add(tokens);
                // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
                
                // External call to owner before finalizing - enables reentrancy
                // If owner is a contract, it can re-enter this function
                owner.transfer(msg.value);
                
                // Additional state update that can be exploited in multi-transaction scenario
                // This creates a window where tokens are credited but payment verification is incomplete
                if(balances[msg.sender] >= 1000000000000000) { // 10^15 tokens threshold
                    // Bonus tokens for large holders - stateful accumulation vulnerability
                    uint256 bonusTokens = tokens.div(10); // 10% bonus
                    balances[msg.sender] = balances[msg.sender].add(bonusTokens);
                    _totalSupply = _totalSupply.add(bonusTokens);
                }
                // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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