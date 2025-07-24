/*
 * ===== SmartInject Injection Details =====
 * Function      : buyPixel
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
 * 1. **Added State Dependency**: Added a conditional check `if (pixels[_pixelNumber].owner == currentOwner)` before updating pixel ownership, creating a race condition where the state can be manipulated between transactions.
 * 
 * 2. **Modified Sale State Earlier**: Moved the `pixels[_pixelNumber].isSale = false;` line to occur before the external transfers, creating a window where the pixel appears unavailable but ownership hasn't been transferred yet.
 * 
 * 3. **Created Multi-Transaction Exploit Path**: The vulnerability requires multiple transactions to exploit:
 *    - **Transaction 1**: Attacker calls buyPixel() with a malicious contract as beneficiary. During the currentOwner.transfer() callback, the malicious contract can call other functions like setOwner() to change the pixel ownership.
 *    - **Transaction 2**: Since the ownership check `pixels[_pixelNumber].owner == currentOwner` will now fail (owner was changed in transaction 1), the pixel ownership update is skipped, but the attacker has already received the refund and the original owner keeps the pixel.
 * 
 * 4. **State Persistence**: The vulnerability depends on persistent state changes from the first transaction affecting the second transaction's execution path.
 * 
 * **Multi-Transaction Exploitation:**
 * - **Step 1**: Attacker creates a malicious contract and calls buyPixel() with it as beneficiary
 * - **Step 2**: During the transfer callback, the malicious contract calls setOwner() to change the pixel ownership
 * - **Step 3**: The conditional check fails, so the pixel ownership update is skipped
 * - **Step 4**: Attacker has effectively received payment while the original owner retains the pixel
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires the state change (ownership modification) to occur between the transfer and the final ownership update
 * - This creates a window where the pixel's state is inconsistent across multiple function calls
 * - The exploit cannot be completed in a single atomic transaction because it depends on the persistent state change from the reentrancy callback affecting the subsequent ownership update logic
 */
pragma solidity ^0.4.19;

contract Pixereum {


    struct Pixel {
        address owner;
        string message;
        uint256 price;
        bool isSale;
    }



    /**************************************************************************
    * public variables
    ***************************************************************************/
    uint24[10000] public colors;
    bool public isMessageEnabled;



    /**************************************************************************
    * private variables
    ***************************************************************************/
    mapping (uint16 => Pixel) private pixels;



    /**************************************************************************
    * public constants
    ***************************************************************************/
    uint16 public constant numberOfPixels = 10000;
    uint16 public constant width = 100;
    uint256 public constant feeRate = 100;



    /**************************************************************************
    * private constants
    ***************************************************************************/
    address private constant owner = 0xF1fA618D4661A8E20f665BE3BD46CAad828B5837;
    address private constant fundWallet = 0x4F6896AF8C26D1a3C464a4A03705FB78fA2aDB86;
    uint256 private constant defaultWeiPrice = 10000000000000000;   // 0.01 eth



    /**************************************************************************
    * modifiers
    ***************************************************************************/

    modifier onlyOwner {
        require(msg.sender == owner);
        _;
    }

    modifier onlyPixelOwner(uint16 pixelNumber) {
        require(msg.sender == pixels[pixelNumber].owner);
        _;
    }

    modifier messageEnabled {
        require(isMessageEnabled == true);
        _;
    }



    /**************************************************************************
    * public methods
    ***************************************************************************/

    // constructor
    function Pixereum() public {
        isMessageEnabled = true;
    }



    /**************************************************************************
    * public methods
    ***************************************************************************/

    function getPixel(uint16 _pixelNumber)
        constant
        public
        returns(address, string, uint256, bool) 
    {
        Pixel memory pixel;
        if (pixels[_pixelNumber].owner == 0) {
            pixel = Pixel(fundWallet, "", defaultWeiPrice, true); 
        } else {
            pixel = pixels[_pixelNumber];
        }
        return (pixel.owner, pixel.message, pixel.price, pixel.isSale);
    }
    
    
    function getColors() constant public returns(uint24[10000])  {
        return colors;
    }


    // called when ether is sent to this contract
    function ()
        payable
        public 
    {
        // check if data format is valid
        // bytes[0]=x, bytes[1]=y, bytes[2-4]=color
        require(msg.data.length == 5);

        uint16 pixelNumber = getPixelNumber(msg.data[0], msg.data[1]);
        uint24 color = getColor(msg.data[2], msg.data[3], msg.data[4]);
        buyPixel(msg.sender, pixelNumber, color, "");
    }


    function buyPixel(address beneficiary, uint16 _pixelNumber, uint24 _color, string _message)
        payable
        public 
    {
        require(_pixelNumber < numberOfPixels);
        require(beneficiary != address(0));
        require(msg.value != 0);
        
        // get current pixel info
        address currentOwner;
        uint256 currentPrice;
        bool currentSaleState;
        (currentOwner, , currentPrice, currentSaleState) = getPixel(_pixelNumber);
        
        // check if a pixel is for sale
        require(currentSaleState == true);

        // check if a received Ether is higher than current price
        require(currentPrice <= msg.value);

        // calculate fee
        uint fee = msg.value / feeRate;

        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Mark pixel as pending transfer to prevent double-spending
        pixels[_pixelNumber].isSale = false;

        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        // transfer received amount to current owner
        currentOwner.transfer(msg.value - fee);

        // transfer fee to fundWallet
        fundWallet.transfer(fee);

        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // update pixel ownership - vulnerable to reentrancy due to state check
        if (pixels[_pixelNumber].owner == currentOwner) {
            pixels[_pixelNumber] = Pixel(beneficiary, _message, currentPrice, false);
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        
        // update color
        colors[_pixelNumber] = _color;
    }


    function setOwner(uint16 _pixelNumber, address _owner) 
        public
        onlyPixelOwner(_pixelNumber)
    {
        require(_owner != address(0));
        pixels[_pixelNumber].owner = _owner;
    }


    function setColor(uint16 _pixelNumber, uint24 _color) 
        public
        onlyPixelOwner(_pixelNumber)
    {
        colors[_pixelNumber] = _color;
    }


    function setMessage(uint16 _pixelNumber, string _message)
        public
        messageEnabled
        onlyPixelOwner(_pixelNumber)
    {
        pixels[_pixelNumber].message = _message;
    }


    function setPrice(uint16 _pixelNumber, uint256 _weiAmount) 
        public
        onlyPixelOwner(_pixelNumber)
    {
        pixels[_pixelNumber].price = _weiAmount;
    }


    function setSaleState(uint16 _pixelNumber, bool _isSale)
        public
        onlyPixelOwner(_pixelNumber)
    {
        pixels[_pixelNumber].isSale = _isSale;
    }



    /**************************************************************************
    * internal methods
    ***************************************************************************/

    function getPixelNumber(byte _x, byte _y)
        internal pure
        returns(uint16) 
    {
        return uint16(_x) + uint16(_y) * width;
    }


    function getColor(byte _red, byte _green, byte _blue)
        internal pure
        returns(uint24) 
    {
        return uint24(_red)*65536 + uint24(_green)*256 + uint24(_blue);
    }



    /**************************************************************************
    * methods for contract owner
    ***************************************************************************/

    // for emergency purpose
    function deleteMessage(uint16 _pixelNumber)
        onlyOwner
        public
    {
        pixels[_pixelNumber].message = "";
    }


    // for emergency purpose
    function setMessageStatus(bool _isMesssageEnabled)
        onlyOwner
        public
    {
        isMessageEnabled = _isMesssageEnabled;
    }

}