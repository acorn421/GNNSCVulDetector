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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to a burn registry contract before state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Transaction 1 (Setup):** Attacker deploys malicious contract and sets it as burnRegistryContract
 * **Transaction 2 (Exploit):** Owner calls burnTokens, triggering external call to malicious contract
 * **During external call:** Malicious contract re-enters burnTokens before state updates complete
 * **Result:** Tokens can be burned multiple times with same balance check
 * 
 * **Multi-Transaction Requirements:**
 * 1. First transaction needed to deploy and configure malicious burn registry
 * 2. Second transaction triggers the actual exploitation through reentrancy
 * 3. The vulnerability exploits the gap between the require check and state updates
 * 4. State from previous transactions (burnRegistryContract address) enables the attack
 * 
 * **Why Multi-Transaction:**
 * - Cannot deploy malicious contract and exploit in same transaction due to contract creation timing
 * - Requires persistent state (burnRegistryContract address) to be set from previous transaction
 * - Exploit depends on accumulated state changes across multiple calls
 * - The attack vector only becomes available after the registry contract is established
 * 
 * The vulnerability violates the Checks-Effects-Interactions pattern by performing external calls before state updates, allowing reentrancy during the window when checks have passed but effects haven't been applied.
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

// Interface for the BurnRegistry contract
contract BurnRegistry {
    function notifyBurn(address _burner, uint256 _value) public;
}

    // ERC20 Token Smart Contract
    contract WeblifeGold {
        
        string public constant name = "WeblifeGold";
        string public constant symbol = "WLG";
        uint8 public constant decimals = 2;
        uint public _totalSupply = 550000000;
        uint256 public RATE = 1;
        bool public isMinting = true;
        string public constant generatedBy  = "Togen.io by Proof Suite";
        
        using SafeMath for uint256;
        address public owner;
        
        // Address of the burn registry contract
        address public burnRegistryContract;
        
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
            owner = 0x53c9e14ed72e88905d4768c53487ab1c013682da; 
            balances[owner] = _totalSupply;
        }

        //allows owner to burn tokens that are not sold in a crowdsale
        function burnTokens(uint256 _value) onlyOwner {

             require(balances[msg.sender] >= _value && _value > 0 );
             // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
             
             // Notify burn registry contract about the burn operation
             if(burnRegistryContract != address(0)) {
                 BurnRegistry(burnRegistryContract).notifyBurn(msg.sender, _value);
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
