/*
 * ===== SmartInject Injection Details =====
 * Function      : depositDai
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 6 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 *
 * === Description ===
 * This injection creates a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added State Tracking**: Introduced `userBalances[msg.sender]` to track cumulative deposits across multiple transactions, creating persistent state that accumulates over time.
 * 
 * 2. **State Update After External Call**: Moved the critical `totalMinted += amount` update to occur AFTER the external DAI transfer, making it vulnerable to reentrancy attacks during the transfer callback.
 * 
 * 3. **Multi-Transaction Callback Mechanism**: Added a conditional callback that only triggers when a user has accumulated deposits across multiple transactions (`userBalances[msg.sender] >= coefficient * 1000000000000000000`). This requires at least 2-3 transactions to reach the threshold.
 * 
 * 4. **Vulnerable External Call**: The `msg.sender.call()` provides a reentrancy vector that allows malicious contracts to re-enter the function during the callback.
 * 
 * **Multi-Transaction Exploitation Path:**
 * - Transaction 1: User deposits normally, builds up `userBalances` but doesn't reach threshold
 * - Transaction 2: User deposits again, reaches threshold, triggers callback
 * - During Transaction 2's callback: Malicious contract can re-enter `depositDai` before `totalMinted` is updated, allowing double-spending of the minting quota
 * - The vulnerability leverages the accumulated state from multiple transactions to create the exploit condition
 * 
 * **Why Multi-Transaction is Required:**
 * - Single transaction cannot exploit because the threshold check requires accumulated balance from previous deposits
 * - The `coefficient` multiplier (minimum 10) ensures multiple transactions are needed to reach the callback threshold
 * - State accumulation across transactions is essential for the vulnerability to be triggered
 */
pragma solidity ^0.4.21;

/*
  BASIC ERC20 Sale Contract
  Create this Sale contract first!
     Sale(address ethwallet)   // this will send the received ETH funds to this address
  @author Hunter Long
  @repo https://github.com/hunterlong/ethereum-ico-contract
*/

contract ERC20 {
  uint public totalSupply;
  uint public maxMintable;
  function balanceOf(address who) constant returns (uint);
  function allowance(address owner, address spender) constant returns (uint);
  function transfer(address to, uint value) returns (bool ok);
  function transferFrom(address from, address to, uint value) returns (bool ok);
  function approve(address spender, uint value) returns (bool ok);
  function mintToken(address to, uint256 value) returns (uint256);
  function changeTransfer(bool allowed);
}

contract Sale {

    uint256 public maxMintable;
    uint256 public totalMinted;
    uint256 public fondTokens;
    uint256 public exchangeRate;
    
    uint public startBlock;
    uint public coefficient;
    bool public isFunding;
    ERC20 public Token;
    address public ETHWallet;

    bool private configSet;
    address public creator;
    address public desiredUsdt = 0xdAC17F958D2ee523a2206206994597C13D831ec7;
    address public desiredUsdc = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
    address public desiredBusd = 0x4Fabb145d64652a948d72533023f6E7A623C7C53;
    address public desiredDai = 0x6B175474E89094C44Da98b954EedeAC495271d0F;

    // Declared userBalances mapping for depositDai vulnerability
    mapping(address => uint256) public userBalances;

    constructor(address _wallet) public {
        startBlock = block.number;
        maxMintable = 1500000000000000000000000000; // 15KKK max sellable (18 decimals)
        totalMinted = 0;
        ETHWallet = _wallet;
        isFunding = false;
        creator = msg.sender;
        exchangeRate = 10;
        fondTokens= 500000000000000000000000000;
        coefficient = 10;
        // createFondTokens();
    }

    // setup function to be ran only 1 time
    // setup token address
    // setup end Block number
    function setup(address token_address) public {
        require(!configSet);
        Token = ERC20(token_address);
        configSet = true;
        createFondTokens();
    }

    function closeSale() external {
      require(msg.sender==creator);
      isFunding = false;
    }
    
    function startSale() external {
      require(msg.sender==creator);
     require(configSet);
      require( isFunding == false);
      isFunding = true;
    }

    // function () payable {
    //     require(msg.value>0);
    //     require(isFunding);
    //     uint256 amount = msg.value * exchangeRate;
    //     uint256 total = totalMinted + amount;
    //     require(total<=maxMintable);
    //     totalMinted += total;
    //     ETHWallet.transfer(msg.value);
    //     Token.mintToken(msg.sender, amount);
    // }

    // CONTRIBUTE FUNCTION
    // converts ETH to TOKEN and sends new TOKEN to the sender
    function depositUsdt(uint256 _amount) external payable {
        require(_amount>1000000000000000000);
        require(isFunding);
        uint256 amount = _amount * exchangeRate;
        uint256 total = totalMinted + amount;
        require(total<=maxMintable);
        totalMinted += amount;
        ERC20(desiredUsdt).transferFrom(msg.sender, ETHWallet, _amount);
        Token.mintToken(msg.sender, amount);
    }

    function depositUsdc(uint256 _amount) external payable {
        require(_amount>1000000000000000000);
        require(isFunding);
        uint256 amount = _amount * exchangeRate;
        uint256 total = totalMinted + amount;
        require(total<=maxMintable);
        totalMinted += amount;
        ERC20(desiredUsdc).transferFrom(msg.sender, ETHWallet, _amount);
        Token.mintToken(msg.sender, amount);
    }


     function depositBusd(uint256 _amount) external payable {
        require(_amount>1000000000000000000);
        require(isFunding);
        uint256 amount = _amount * exchangeRate;
        uint256 total = totalMinted + amount;
        require(total<=maxMintable);
        totalMinted += amount;
        ERC20(desiredBusd).transferFrom(msg.sender, ETHWallet, _amount);
        Token.mintToken(msg.sender, amount);
    }

     function depositDai(uint256 _amount) external payable {
        require(_amount>1000000000000000000);
        require(isFunding);
        uint256 amount = _amount * exchangeRate;
        uint256 total = totalMinted + amount;
        require(total<=maxMintable);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Add user balance tracking for multi-transaction state
        userBalances[msg.sender] += amount;
        
        // External call to DAI contract before updating critical state
        ERC20(desiredDai).transferFrom(msg.sender, ETHWallet, _amount);
        
        // State update moved after external call - vulnerable to reentrancy
        totalMinted += amount;
        
        // Check if user has accumulated enough balance across multiple transactions
        if (userBalances[msg.sender] >= coefficient * 1000000000000000000) {
            // Callback to user's contract for "bonus calculation" - reentrancy vector
            if (msg.sender.call(bytes4(keccak256("calculateBonus(uint256)")), userBalances[msg.sender])) {
                // Bonus tokens minted based on accumulated balance
                uint256 bonusAmount = userBalances[msg.sender] / 10;
                Token.mintToken(msg.sender, bonusAmount);
            }
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        Token.mintToken(msg.sender, amount);
    }

    // update the USD/COIN rate
    function updateRate(uint256 rate) external {
        require(msg.sender==creator);
        exchangeRate = rate;
    }

    function updateCoefficient(uint256 _coefficient) external {
        require(msg.sender==creator);
        require(10<_coefficient);
        require(_coefficient<50);
        coefficient = _coefficient;
    }

    

    // change creator address
    function changeCreator(address _creator) external {
        require(msg.sender==creator);
        creator = _creator;
    }

    function changeEthWallet(address ethWallet) external {
        require(msg.sender==creator);
        ETHWallet = ethWallet;
    }


    function createFondTokens() internal {
        // TOTAL SUPPLY = 5,000,000
     require(msg.sender==creator);
     Token.mintToken(ETHWallet, fondTokens);         
    }
}
