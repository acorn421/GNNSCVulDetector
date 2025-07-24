/*
 * ===== SmartInject Injection Details =====
 * Function      : setOwner
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the old owner before updating the owner state. This creates a classic reentrancy pattern where:
 * 
 * 1. **External Call Before State Update**: The function calls the old owner contract via `oldOwner.call()` before updating the `owner` state variable
 * 2. **Stateful Nature**: The vulnerability depends on the contract having a current owner that is different from the new owner
 * 3. **Multi-Transaction Exploitation**: Requires multiple transactions to set up and exploit:
 *    - Transaction 1: Deploy malicious contract and set it as owner
 *    - Transaction 2: Call setOwner with a new address, triggering the external call to the malicious contract
 *    - Transaction 3+: Malicious contract re-enters during the callback to exploit the intermediate state
 * 
 * **Exploitation Scenario:**
 * - Attacker first becomes owner through legitimate means or social engineering
 * - Attacker calls setOwner() with a new address (could be legitimate or another attacker contract)
 * - During the external call to the old owner (attacker's contract), the attacker re-enters the contract
 * - At this point, `owner` still points to the attacker's contract, allowing them to call other onlyOwner functions
 * - The attacker can drain funds via withdrawEther(), withdrawERC20Tokens(), or manipulate token prices via setWeiPerToken()
 * 
 * **Why Multi-Transaction:**
 * - Requires initial setup to become owner (Transaction 1)
 * - Vulnerability is only triggered when ownership transfer occurs (Transaction 2)
 * - Exploitation happens during the callback, potentially spanning multiple re-entrant calls
 * - The vulnerability persists across the state transition period, enabling complex multi-call attacks
 * 
 * This pattern is realistic as many contracts implement ownership transfer notifications for integration with external systems, making it a subtle and dangerous vulnerability.
 */
pragma solidity ^0.4.25;
// Interface to ERC20 functions used in this contract
interface ERC20token {
    //function balanceOf(address who) external view returns (uint256);
    //function balanceOf(address _owner) constant returns (uint256 balance) {}
    function balanceOf(address who) constant returns (uint);
    function transfer(address to, uint256 value) external returns (bool);
    function allowance(address owner, address spender) external view returns (uint256);
    function transferFrom(address from, address to, uint256 value) external returns (bool);
}
contract ExoTokensMarketSimple {
    ERC20token ExoToken;
    address owner;
    uint256 weiPerToken;
    uint8 decimals;

    modifier onlyOwner {
        require(msg.sender == owner);
        _;
    }
    constructor() public {
        owner = msg.sender;
        weiPerToken = 1000000000000000;
        decimals = 3;
    }

    function setWeiPerToken(uint256 _weiPerToken) public onlyOwner {
        weiPerToken = _weiPerToken;
    }
    function getWeiPerToken() public view returns(uint256) {
        return weiPerToken;
    }
    function setERC20Token(address tokenAddr) public onlyOwner  {
        ExoToken = ERC20token(tokenAddr);
    }
    function getERC20Token() public view returns(address) {
        return ExoToken;
    }
    function getERC20Balance() public view returns(uint256) {
        return ExoToken.balanceOf(this);
    }
    function depositERC20Token(uint256 _exo_amount) public  {
        require(ExoToken.allowance(msg.sender, this) >= _exo_amount);
        require(ExoToken.transferFrom(msg.sender, this, _exo_amount));
    }

    // ERC20(GUP) buying function
    // All of the ETH included in the TX is converted to GUP
    function BuyTokens() public payable{
        require(msg.value > 0, "eth value must be non zero");
        uint256 exo_balance = ExoToken.balanceOf(this);
        uint256 tokensToXfer = (msg.value/weiPerToken)*(10**18);
        require(exo_balance >= tokensToXfer, "Not enough tokens in contract");
        require(ExoToken.transfer(msg.sender, tokensToXfer), "Couldn't send funds");
    }

    // Withdraw erc20 tokens
    function withdrawERC20Tokens(uint _val) public onlyOwner {
        require(ExoToken.transfer(msg.sender, _val), "Couldn't send funds"); // send EXO tokens
    }

    // Withdraw Ether
    function withdrawEther() public onlyOwner {
        msg.sender.transfer(address(this).balance);

    }
 
    // change the owner
    function setOwner(address _owner) public onlyOwner {
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        address oldOwner = owner;
        
        // Notify old owner of ownership transfer (vulnerable external call)
        if (oldOwner != address(0) && oldOwner != msg.sender) {
            // External call before state update - creates reentrancy vulnerability
            (bool success, ) = oldOwner.call(abi.encodeWithSignature("ownershipTransferred(address,address)", msg.sender, _owner));
            // Continue execution regardless of call result
        }
        
        // State update happens after external call
        owner = _owner;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    }
    // fallback
    function() external payable { }   
}