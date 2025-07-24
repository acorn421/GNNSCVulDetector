/*
 * ===== SmartInject Injection Details =====
 * Function      : depositBoth
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
 * 1. reentrancy-benign (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added State Variables**: Introduced `pendingDeposits`, `pendingEthDeposits`, `totalPendingChi`, and `totalPendingEth` mappings/variables that track deposit states across transactions.
 * 
 * 2. **Moved State Updates**: Placed critical state updates (`totalPendingChi += _chi_amount` and `totalPendingEth += msg.value`) after the external `transferFrom` call, violating the checks-effects-interactions pattern.
 * 
 * 3. **Added Callback Mechanism**: Introduced an external callback (`onDepositReceived`) that can be triggered during the deposit process, creating a reentrancy vector.
 * 
 * 4. **Multi-Transaction Exploitation Path**:
 *    - **Transaction 1**: Attacker (as owner) calls `depositBoth` with malicious ChiToken
 *    - **During transferFrom**: Malicious contract calls back to other ChiMarket functions (like `limitSell`, `limitBuy`, `withdrawBoth`)
 *    - **Exploitation**: These callbacks can read the updated `pendingDeposits` but the `totalPendingChi/Eth` hasn't been finalized yet, creating inconsistent state
 *    - **Transaction 2+**: Attacker can exploit accumulated pending deposits and the inconsistent state between individual pending amounts and total pending amounts
 * 
 * 5. **Stateful Nature**: The vulnerability relies on the persistent state in `pendingDeposits` and `pendingEthDeposits` mappings that accumulate across multiple transactions, making it impossible to exploit in a single atomic transaction.
 * 
 * 6. **Realistic Integration**: The changes appear as legitimate functionality for tracking deposits and implementing callback notifications, making the vulnerability subtle and realistic.
 * 
 * The vulnerability requires multiple transactions because:
 * - The inconsistent state between pending individual deposits and total pending amounts must be accumulated
 * - The callback mechanism allows for complex multi-step exploitation patterns
 * - The attacker needs to build up state across multiple calls to maximize the exploit potential
 */
pragma solidity ^0.4.21;

// Interface to ERC721 functions used in this contract
interface ERC20token {
    function balanceOf(address who) external view returns (uint256);
    function transfer(address to, uint256 value) external returns (bool);
    function allowance(address owner, address spender) external view returns (uint256);
    function transferFrom(address from, address to, uint256 value) external returns (bool);
}
// Interface to ERC721 functions used in this contract
interface ERC721Token {
    function transferFrom(address _from, address _to, uint256 _tokenId) external payable;
}

contract ChiMarket {
    ERC20token ChiToken = ERC20token(0x71E1f8E809Dc8911FCAC95043bC94929a36505A5);
    address owner;
    uint256 market_halfspread;

    // Added variable declarations to fix compilation errors
    mapping(address => uint256) public pendingDeposits;
    mapping(address => uint256) public pendingEthDeposits;
    uint256 public totalPendingChi;
    uint256 public totalPendingEth;

    modifier onlyOwner {
        require(msg.sender == owner);
        _;
    }

    constructor() public {
        owner = msg.sender;
    }

    // Calculate the amount of ETH the contract pays out on a SELL
    function calcSELLoffer(uint256 chi_amount) public view returns(uint256){
        uint256 eth_balance = address(this).balance;
        uint256 chi_balance = ChiToken.balanceOf(this);
        uint256 eth_amount;
        require(eth_balance > 0 && chi_balance > 0);

        require(chi_balance + chi_amount >= chi_balance); // don't allow overflow
        eth_amount = (chi_amount * eth_balance) / (chi_balance + chi_amount);
        require(1000 * eth_amount >= eth_amount); // don't allow overflow
        eth_amount = ((1000 - market_halfspread) * eth_amount) / 1000;
        return eth_amount;
    }

    // Calculate the amount of ETH the contract requires on a BUY
    // When this function is called from a payable function, the balance is updated
    // already, so we need to subtract it through _offset_eth. Otherwise _offset_eth
    // should be set to 0.
    function calcBUYoffer(uint256 _chi_amount, uint256 _offset_eth) public view returns(uint256){
        require(address(this).balance > _offset_eth); // no overflow
        uint256 eth_balance = address(this).balance - _offset_eth;
        uint256 chi_balance = ChiToken.balanceOf(this);
        uint256 eth_amount;
        require(eth_balance > 0 && chi_balance > 0);
        require(chi_balance > _chi_amount); // must have enough CHI
        
        require(chi_balance - _chi_amount <= chi_balance); // don't allow overflow
        eth_amount = (_chi_amount * eth_balance) / (chi_balance - _chi_amount);
        require(1000 * eth_amount >= eth_amount); // don't allow overflow
        eth_amount = (1000 * eth_amount) / (1000 - market_halfspread);
        return eth_amount;
    }

    // CHI buying function
    // All of the ETH included in the TX is converted to CHI
    // requires at least _min_chi_amount of CHI for that ETH, otherwise TX fails
    function limitBuy(uint256 _chi_amount) public payable{
        require(_chi_amount > 0);
        uint256 eth_amount = calcBUYoffer(_chi_amount, msg.value);
        require(eth_amount <= msg.value);
        uint256 return_ETH_amount = msg.value - eth_amount;
        require(return_ETH_amount < msg.value);

        if(return_ETH_amount > 0){
            msg.sender.transfer(return_ETH_amount); // return extra ETH
        }
        require(ChiToken.transfer(msg.sender, _chi_amount)); // send CHI tokens
    }

    // CHI selling function.
    // sell _chi_amount of CHI
    // require at least _min_eth_amount for that CHI, otherwise TX fails
    // Make sure to set CHI allowance before calling this function
    function limitSell(uint256 _chi_amount, uint256 _min_eth_amount) public {
        require(ChiToken.allowance(msg.sender, this) >= _chi_amount);
        uint256 eth_amount = calcSELLoffer(_chi_amount);
        require(eth_amount >= _min_eth_amount);
        require(eth_amount > 0);

        require(ChiToken.transferFrom(msg.sender, this, _chi_amount));
        msg.sender.transfer(eth_amount);
    }

    // Allows owner to move CHI (e.g. to an updated contract), also to rescue 
    // other ERC20 tokens sent by mistake.    
    function moveERC20Tokens(address _tokenContract, address _to, uint _val) public onlyOwner {
        ERC20token token = ERC20token(_tokenContract);
        require(token.transfer(_to, _val));
    }

    // Hopefully this doesn't get used, but it allows for gotchi rescue if someone sends
    // their gotchi (or a cat) to the contract by mistake.
    function moveERC721Tokens(address _tokenContract, address _to, uint256 _tid) public onlyOwner {
        ERC721Token token = ERC721Token(_tokenContract);
        token.transferFrom(this, _to, _tid);
    }

    // Allows the owner to move ether, for example to an updated contract  
    function moveEther(address _target, uint256 _amount) public onlyOwner {
        require(_amount <= address(this).balance);
        _target.transfer(_amount);
    }

    // Set the market spread (actually it's half of the spread).    
    function setSpread(uint256 _halfspread) public onlyOwner {
        require(_halfspread <= 50);
        market_halfspread = _halfspread;        
    }
 
    // Allows for deposit of ETH and CHI at the same time (to avoid temporary imbalance
    // in the market)
    function depositBoth(uint256 _chi_amount) public payable onlyOwner {
        require(ChiToken.allowance(msg.sender, this) >= _chi_amount);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Track deposit for later processing
        pendingDeposits[msg.sender] += _chi_amount;
        pendingEthDeposits[msg.sender] += msg.value;
        
        // External call before state finalization - vulnerable to reentrancy
        require(ChiToken.transferFrom(msg.sender, this, _chi_amount));
        
        // State finalization occurs after external call
        totalPendingChi += _chi_amount;
        totalPendingEth += msg.value;
        
        // Notify callback mechanism (potential reentrancy vector)
        if (address(ChiToken).call(bytes4(keccak256("onDepositReceived(address,uint256)")), msg.sender, _chi_amount)) {
            // Callback succeeded - this creates a window for reentrancy
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    }

    // Allows for withdrawal of ETH and CHI at the same time (to avoid temporary imbalance
    // in the market)
    function withdrawBoth(uint256 _chi_amount, uint256 _eth_amount) public onlyOwner {
        uint256 eth_balance = address(this).balance;
        uint256 chi_balance = ChiToken.balanceOf(this);
        require(_chi_amount <= chi_balance);
        require(_eth_amount <= eth_balance);
        
        msg.sender.transfer(_eth_amount);
        require(ChiToken.transfer(msg.sender, _chi_amount));
    }
 
    // change the owner
    function setOwner(address _owner) public onlyOwner {
        owner = _owner;    
    }

    // empty fallback payable to allow ETH deposits to the contract    
    function() public payable{
    }
}
