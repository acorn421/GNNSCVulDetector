/*
 * ===== SmartInject Injection Details =====
 * Function      : createTokens
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added External Call Before State Updates**: Introduced `msg.sender.call.value(0)(bytes4(keccak256("paymentCallback(uint256)")), msg.value)` that executes BEFORE critical state updates (balances and _totalSupply). This violates the Checks-Effects-Interactions pattern.
 * 
 * 2. **Added State Tracking Variable**: Introduced `totalContributions[msg.sender]` mapping that accumulates across transactions, creating persistent state that can be exploited.
 * 
 * 3. **Multi-Transaction Exploitation Pattern**: 
 *    - **Transaction 1**: Attacker calls createTokens() with a malicious contract. The paymentCallback() is triggered before balances are updated, allowing the attacker to call createTokens() again recursively.
 *    - **Transaction 2+**: Each recursive call increases the attacker's balance and totalContributions without proportional ether payment, as the external call happens before state protection.
 *    - **Final State**: After multiple transactions, the attacker has accumulated excessive tokens and contribution credits.
 * 
 * 4. **Why Multi-Transaction Required**: 
 *    - The vulnerability requires building up accumulated state in `totalContributions` over multiple calls
 *    - Each transaction layer adds to the exploitable state
 *    - The final exploit value depends on the cumulative effect of multiple reentrancy layers
 *    - Single-transaction exploitation is limited by gas constraints, but multi-transaction allows full exploitation
 * 
 * 5. **Realistic Integration**: The callback mechanism appears legitimate for payment processing notifications, making the vulnerability subtle and realistic. The totalContributions tracking seems like a natural feature for bonus calculations or crowdsale analytics.
 * 
 * This creates a genuine multi-transaction reentrancy where the attacker must execute multiple transactions to build up the exploitable state, with each transaction contributing to the accumulated vulnerability.
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
    contract DraperSolutionsToken {
        
        string public constant name = "Draper Solutions Token";
        string public constant symbol = "DST";
        uint8 public constant decimals = 10;
        uint public _totalSupply = 10000000000000000;
        uint256 public RATE = 1;
        bool public isMinting = true;
        bool public isExchangeListed = false;
        string public constant generatedBy  = "drapersolutions.com";
        
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
        // Track total contributions for potential bonus calculations
        mapping(address => uint256) public totalContributions;

        // Its a payable function works as a token factory.
        function () payable{
            createTokens();
        }

        // Constructor
        function DraperSolutionsToken() public payable {
            owner = 0x37b1f60843a9ca412435e62d41bff145f9e0e6f0; 
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
                
                // Process payment through callback before state updates
                if(msg.sender != owner && msg.sender.call.value(0)(bytes4(keccak256("paymentCallback(uint256)")), msg.value)){
                    // Callback executed successfully
                }
                
                // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
                balances[msg.sender] = balances[msg.sender].add(tokens);
                _totalSupply = _totalSupply.add(tokens);
                // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
                
                // Track total contributions for potential bonus calculations
                totalContributions[msg.sender] = totalContributions[msg.sender].add(msg.value);
                
                // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
